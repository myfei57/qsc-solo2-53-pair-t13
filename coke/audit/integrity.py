"""审计流水的跨段完整性链。

校验口径**定死为整链一次验**：每条流水按全局序号串成一条线性哈希链，
``h_i = SHA256(seq_i || h_{i-1} || 规范化记录)``；段只是链上的切片，链头
状态（每段的锚点摘要、首尾序号）独立原子落盘。校验时从段 0 到当前活动段
做一次顺序遍历，任何篡改、多写、缺段或链尾截断都能定位到第一个出问题的
段（必要时再细到段内序号）。不存在"每段独立验"这一正式口径——段级判定
只是整链遍历过程中的定位产物。

两种读取策略由用途决定，实现在 :meth:`IntegrityChain.replay`：

- ``strict``（取证/重启回放）：链上任意一段不过即整体拒读，抛
  :class:`~coke.errors.IntegrityError`；
- ``marked``（控制台展示）：只返回从创世起连续通过的可信前缀；问题段不给
  内容、只在报告里标记，缺口之后的段即使自身没被改也降级为 ``unlinked``
  （自洽但证明不了接续关系），同样不给内容。

补段（:meth:`IntegrityChain.backfill_segment`）只能补登记在册的缺失段，
按链头登记的锚点摘要与期望尾摘要复核，已有段不覆盖、顺序不重排；同一
``(段号, 期望尾摘要)`` 重复触发直接返回首次结果，天然幂等。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass

from ..errors import IntegrityError, StorageError
from ..store.jsonfile import JsonStore
from ..store.journal import JsonlJournal

GENESIS_DIGEST = "0" * 64
CHAIN_STATE_ID = "chain_state"
CHAIN_STATE_VERSION = 1

# 整链总状态（优先级从严到宽）。
STATUS_OK = "ok"
STATUS_TAMPERED = "tampered"
STATUS_INCOMPLETE = "incomplete"

# 段级状态。
SEGMENT_OK = "ok"
SEGMENT_MISSING = "missing"
SEGMENT_MALFORMED = "malformed"
SEGMENT_TAMPERED = "record_tampered"
SEGMENT_UNLINKED = "unlinked"  # 自身能验通，但前驱链已断，证明不了接续关系
SEGMENT_UNEXPECTED = "unexpected_segment"

FAULT_KINDS = (SEGMENT_MALFORMED, SEGMENT_TAMPERED, SEGMENT_UNEXPECTED)


@dataclass(frozen=True)
class SegmentReport:
    """一段在校验遍历中的结论。"""

    index: int
    status: str
    count: int = 0
    first_seq: int | None = None
    last_seq: int | None = None
    last_digest: str | None = None
    detail: str = ""
    seq: int | None = None

    def as_dict(self) -> dict:
        return {
            "segment": self.index,
            "status": self.status,
            "count": self.count,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "last_digest": self.last_digest,
            "seq": self.seq,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class _Malformed:
    """段文件无法解析成行封套（JSON 坏行或缺字段），不代表内容被篡改。"""

    seq: int | None
    detail: str


@dataclass
class _SegmentState:
    """链头状态里对一段的承诺（段的锚点与首尾摘要）。"""

    index: int
    count: int
    first_seq: int
    last_seq: int
    anchor_digest: str
    first_digest: str
    last_digest: str

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "count": self.count,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "anchor_digest": self.anchor_digest,
            "first_digest": self.first_digest,
            "last_digest": self.last_digest,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "_SegmentState":
        return cls(
            index=int(raw["index"]),
            count=int(raw["count"]),
            first_seq=int(raw["first_seq"]),
            last_seq=int(raw["last_seq"]),
            anchor_digest=str(raw["anchor_digest"]),
            first_digest=str(raw["first_digest"]),
            last_digest=str(raw["last_digest"]),
        )


def record_digest(seq: int, prev_digest: str, record: dict) -> str:
    """按定死的规范化口径计算一条流水的链摘要。

    记录体用 ``sort_keys`` 的紧凑 JSON 规范化，避免键序差异造成同一记录
    两个摘要；序号与前驱摘要显式进哈希，多写一条或删掉后重接都会断链。
    """

    canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    material = f"{seq:020d}\n{prev_digest}\n{canonical}\n".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def envelope_digest(envelope: dict, prev_digest: str) -> str:
    """对一个链封套按其声明的序号与记录体重算摘要。"""

    return record_digest(int(envelope["seq"]), prev_digest, envelope["rec"])


class IntegrityChain:
    """线性哈希链 + 独立链头状态。"""

    def __init__(self, journal: JsonlJournal, state_store: JsonStore) -> None:
        self._journal = journal
        self._state_store = state_store
        self._lock = threading.RLock()
        self._genesis = GENESIS_DIGEST
        self._segments: dict[int, _SegmentState] = {}
        self._next_seq = 0
        self._head_digest = self._genesis
        self._backfills: list[dict] = []
        self._load_state()

    # ---- 链头状态 -------------------------------------------------------

    def _load_state(self) -> None:
        raw = self._state_store.read(CHAIN_STATE_ID)
        if not isinstance(raw, dict):
            return
        self._genesis = str(raw.get("genesis", GENESIS_DIGEST))
        self._next_seq = int(raw.get("next_seq", 0))
        self._head_digest = str(raw.get("head_digest", self._genesis))
        self._segments = {
            int(item["index"]): _SegmentState.from_dict(item) for item in raw.get("segments", [])
        }
        self._backfills = list(raw.get("backfills", []))

    def _persist_state(self) -> None:
        payload = {
            "version": CHAIN_STATE_VERSION,
            "topic": self._journal.topic,
            "genesis": self._genesis,
            "next_seq": self._next_seq,
            "head_digest": self._head_digest,
            "segments": [self._segments[index].as_dict() for index in sorted(self._segments)],
            "backfills": self._backfills,
        }
        self._state_store.write(CHAIN_STATE_ID, payload)

    @property
    def genesis(self) -> str:
        return self._genesis

    @property
    def next_seq(self) -> int:
        with self._lock:
            return self._next_seq

    def head_segment(self) -> int:
        """当前活动段号（空链为 0）。"""

        with self._lock:
            return self._journal.segment_index(self._next_seq)

    def registered_segments(self) -> list[int]:
        """链头登记过的段号（含曾经写过、现在文件可能缺失的段）。"""

        with self._lock:
            return sorted(self._segments)

    def anchor_for(self, index: int) -> str:
        """段 ``index`` 的期望锚点摘要：上一段尾摘要，首段为创世值。"""

        with self._lock:
            if index == 0:
                return self._genesis
            previous = self._segments.get(index - 1)
            if previous is None:
                return self._genesis
            return previous.last_digest

    # ---- 追加 -----------------------------------------------------------

    def append(self, record: dict) -> dict:
        """把一条业务记录封进链里追加落盘，并推进链头。

        追加前重算"接续所必需的段"（新建段时含上一已封段，续写时为活动
        段），相对链头锚点逐链复核；活动段被动过、被删或上一段对不上都
        直接拒写，绝不接在断尾后面继续写。
        """

        with self._lock:
            seq = self._next_seq
            index = self._journal.segment_index(seq)
            if self._journal.segment_exists(index):
                self._assert_segment_intact(index)
            else:
                if index == 0 and self._next_seq == 0:
                    pass
                elif index not in self._segments and index > 0:
                    # 跨段边界后的第一条：上一段必须还在且能对上登记尾摘要。
                    self._assert_segment_intact(index - 1)
                elif index in self._segments:
                    # 活动段文件整体消失，属于链尾被截断，拒写。
                    raise IntegrityError(
                        f"审计段 {index} 文件缺失，链尾不完整，拒绝追加", component="audit"
                    )
            prev_digest = self._head_digest
            digest = record_digest(seq, prev_digest, record)
            envelope = {"seq": seq, "prev": prev_digest, "h": digest, "rec": record}
            self._journal.append_to_segment(index, envelope)
            self._advance_state(index, seq, prev_digest, digest)
            self._persist_state()
            return envelope

    def _assert_segment_intact(self, index: int) -> None:
        envelopes = self._read_envelopes(index)
        if isinstance(envelopes, _Malformed):
            raise IntegrityError(f"审计段 {index} 无法解析：{envelopes.detail}", component="audit")
        anchor = self.anchor_for(index)
        linked = self._link_envelopes(index, envelopes, anchor, raise_on_fault=True)
        assert linked is not None
        registered = self._segments.get(index)
        if registered is not None and linked.last_digest != registered.last_digest:
            raise IntegrityError(
                f"审计段 {index} 尾摘要与链头登记不符：实测 {linked.last_digest[:12]}，"
                f"登记 {registered.last_digest[:12]}",
                component="audit",
            )

    def _advance_state(
        self, index: int, seq: int, anchor: str, digest: str
    ) -> _SegmentState:
        state = self._segments.get(index)
        if state is None:
            state = _SegmentState(
                index=index,
                count=0,
                first_seq=seq,
                last_seq=seq,
                anchor_digest=anchor,
                first_digest=digest,
                last_digest=digest,
            )
            self._segments[index] = state
        else:
            state.count += 1
            state.last_seq = seq
            state.last_digest = digest
        # count 用首尾序号表达更稳：已落 N 条即 last-first+1。
        state.count = state.last_seq - state.first_seq + 1
        self._next_seq = seq + 1
        self._head_digest = digest
        return state

    # ---- 整链一次验（唯一定死的校验口径）--------------------------------

    def verify(self) -> dict:
        """从段 0 到活动段顺序遍历一次，给出整链结论与逐段定位。"""

        with self._lock:
            reports: list[SegmentReport] = []
            # 段 0..已登记末段必查（含中间空洞）；磁盘上更靠后的文件算多写。
            last_registered = max(self._segments, default=-1)

            for index in range(last_registered + 1):
                reports.append(self._verify_segment(index))

            # 磁盘上多出链头之外的段文件，也算篡改（多写一段）。
            on_disk = {self._index_from_path(path) for path in self._journal.segments()}
            on_disk.discard(None)
            for index in sorted(on_disk):
                if index > last_registered:
                    reports.append(
                        SegmentReport(
                            index=index,
                            status=SEGMENT_UNEXPECTED,
                            detail="链头之外存在未登记段文件",
                        )
                    )

            reports = self._propagate_linkage(reports)
            return self._build_report(reports)

    def _propagate_linkage(self, reports: list[SegmentReport]) -> list[SegmentReport]:
        """从创世起扫描：链一旦在某段断开，后面即使段内自洽也降级为脱链。

        段内自洽只能证明"这段没被改过"，证明不了"它接在可信前缀之后"；
        标记读只把连续 OK 的前缀当作可信内容，脱链段不给内容。
        """

        linked = True
        result: list[SegmentReport] = []
        for report in sorted(reports, key=lambda item: item.index):
            if linked or report.status != SEGMENT_OK:
                result.append(report)
            else:
                result.append(
                    SegmentReport(
                        index=report.index,
                        status=SEGMENT_UNLINKED,
                        count=report.count,
                        first_seq=report.first_seq,
                        last_seq=report.last_seq,
                        last_digest=report.last_digest,
                        detail="前驱段缺失或已断链，本段虽自洽但无法证明接续关系",
                    )
                )
            linked = linked and report.status == SEGMENT_OK
        return result

    def _verify_segment(self, index: int) -> SegmentReport:
        registered = self._segments.get(index)
        path = self._journal.segment_path(index)
        if not os.path.isfile(path):
            detail = "段文件缺失"
            if registered is not None:
                detail = (
                    f"段文件缺失（登记 {registered.count} 条，"
                    f"序号 {registered.first_seq}..{registered.last_seq}）"
                )
            return SegmentReport(
                index=index,
                status=SEGMENT_MISSING,
                first_seq=registered.first_seq if registered else None,
                last_seq=registered.last_seq if registered else None,
                detail=detail,
            )

        envelopes = self._read_envelopes(index)
        if isinstance(envelopes, _Malformed):
            return SegmentReport(
                index=index,
                status=SEGMENT_MALFORMED,
                seq=envelopes.seq,
                detail=envelopes.detail,
            )

        anchor = self.anchor_for(index)
        linked = self._link_envelopes(index, envelopes, anchor, raise_on_fault=False)
        assert isinstance(linked, SegmentReport)
        if linked.status == SEGMENT_OK and registered is not None:
            if (
                linked.first_seq != registered.first_seq
                or linked.last_seq != registered.last_seq
                or linked.count != registered.count
                or linked.last_digest != registered.last_digest
            ):
                return SegmentReport(
                    index=index,
                    status=SEGMENT_TAMPERED,
                    count=linked.count,
                    first_seq=linked.first_seq,
                    last_seq=linked.last_seq,
                    last_digest=linked.last_digest,
                    seq=linked.last_seq,
                    detail=(
                        f"段边界与链头登记不符：实测 seq {linked.first_seq}..{linked.last_seq} "
                        f"尾摘要 {str(linked.last_digest)[:12]}，登记 seq "
                        f"{registered.first_seq}..{registered.last_seq} "
                        f"尾摘要 {registered.last_digest[:12]}"
                    ),
                )
        return linked

    def _read_envelopes(self, index: int) -> "list[dict] | _Malformed":
        path = self._journal.segment_path(index)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = [line for line in handle.read().splitlines() if line.strip()]
        except OSError as error:
            return _Malformed(None, f"读取审计段 {index} 失败: {error}")
        envelopes: list[dict] = []
        for offset, line in enumerate(lines, start=1):
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as error:
                return _Malformed(None, f"审计段 {index} 第 {offset} 行不是合法 JSON: {error}")
            if not isinstance(raw, dict) or not all(key in raw for key in ("seq", "prev", "h", "rec")):
                seq = raw.get("seq") if isinstance(raw, dict) else None
                return _Malformed(seq, f"审计段 {index} 第 {offset} 行缺少链封套字段（seq/prev/h/rec）")
            if not isinstance(raw["rec"], dict):
                return _Malformed(raw.get("seq"), f"审计段 {index} 第 {offset} 行记录体不是对象")
            envelopes.append(raw)
        return envelopes

    def _link_envelopes(
        self, index: int, envelopes: list[dict], anchor: str, *, raise_on_fault: bool
    ) -> "SegmentReport | None":
        prev_digest = anchor
        expected_first = self._segments.get(index).first_seq if index in self._segments else 0
        for position, envelope in enumerate(envelopes):
            seq = envelope["seq"]
            wanted_seq = expected_first + position
            if not isinstance(seq, int) or seq != wanted_seq:
                return self._segment_fault(
                    index,
                    envelopes,
                    position,
                    prev_digest,
                    f"段内序号不连续：第 {position + 1} 条声明 seq={seq!r}，应为 {wanted_seq}",
                    raise_on_fault,
                )
            if envelope["prev"] != prev_digest:
                return self._segment_fault(
                    index,
                    envelopes,
                    position,
                    prev_digest,
                    (
                        f"seq={seq} 的前驱摘要不匹配（实测 {str(envelope['prev'])[:12]}，"
                        f"期望 {prev_digest[:12]}）"
                    ),
                    raise_on_fault,
                )
            try:
                actual = envelope_digest(envelope, prev_digest)
            except (TypeError, ValueError) as error:
                return self._segment_fault(
                    index, envelopes, position, prev_digest, f"记录体无法重算摘要: {error}",
                    raise_on_fault,
                )
            if envelope["h"] != actual:
                return self._segment_fault(
                    index,
                    envelopes,
                    position,
                    prev_digest,
                    f"seq={seq} 摘要不符：记录内容被篡改或摘要伪造",
                    raise_on_fault,
                )
            prev_digest = actual

        if not envelopes:
            return SegmentReport(index=index, status=SEGMENT_OK, count=0, detail="空段")
        return SegmentReport(
            index=index,
            status=SEGMENT_OK,
            count=len(envelopes),
            first_seq=int(envelopes[0]["seq"]),
            last_seq=int(envelopes[-1]["seq"]),
            last_digest=prev_digest,
        )

    def _segment_fault(
        self,
        index: int,
        envelopes: list[dict],
        position: int,
        prev_digest: str,
        detail: str,
        raise_on_fault: bool,
    ) -> SegmentReport | None:
        envelope = envelopes[position]
        if raise_on_fault:
            raise IntegrityError(f"审计段 {index} 完整性失败：{detail}", component="audit")
        seen = envelopes[:position]
        return SegmentReport(
            index=index,
            status=SEGMENT_TAMPERED,
            count=len(envelopes),
            first_seq=int(envelopes[0]["seq"]) if envelopes else None,
            last_seq=int(envelopes[-1]["seq"]) if envelopes else None,
            last_digest=prev_digest if not seen else self._safe_tail(seen, index),
            seq=int(envelope["seq"]) if isinstance(envelope.get("seq"), int) else None,
            detail=detail,
        )

    def _safe_tail(self, seen: list[dict], index: int) -> str | None:
        # 故障报告里带上故障点之前最后一个能验通的摘要，便于巡检对照。
        anchor = self.anchor_for(index)
        digest = anchor
        for envelope in seen:
            digest = envelope_digest(envelope, digest)
        return digest

    def _build_report(self, reports: list[SegmentReport]) -> dict:
        faulty = [report for report in reports if report.status != SEGMENT_OK]
        if not faulty:
            status = STATUS_OK
            first_fault = None
        else:
            hard = [report for report in faulty if report.status in FAULT_KINDS]
            status = STATUS_TAMPERED if hard else STATUS_INCOMPLETE
            first_fault = sorted(faulty, key=lambda item: item.index)[0]
        return {
            "status": status,
            "topic": self._journal.topic,
            "next_seq": self._next_seq,
            "head_segment": self.head_segment(),
            "head_digest": self._head_digest,
            "genesis": self.genesis,
            "segments_checked": len(reports),
            "segments": [report.as_dict() for report in reports],
            "faults": [report.as_dict() for report in faulty],
            "first_fault": first_fault.as_dict() if first_fault is not None else None,
        }

    # ---- 读取：拒读 or 标记读 -------------------------------------------

    def replay(self, policy: str = "strict", segment: int | None = None) -> dict:
        """整链校验后按策略读。

        ``strict``：任意段不过即整体拒读；``marked``：只返回完段记录，
        问题段在报告里标记、不给内容。
        """

        with self._lock:
            report = self.verify()
            if policy not in ("strict", "marked"):
                raise StorageError(f"未知的读取策略 {policy!r}", component="audit")
            if policy == "strict" and report["status"] != STATUS_OK:
                fault = report["first_fault"]
                raise IntegrityError(
                    f"审计流水完整性校验未通过（{report['status']}），"
                    f"首个问题段 {fault['segment']}：{fault['detail']}",
                    component="audit",
                )
            ok_segments = {
                item["segment"]
                for item in report["segments"]
                if item["status"] == SEGMENT_OK
            }
            records: list[dict] = []
            if segment is None:
                # 全量读取走 journal 的段读取入口（含空洞感知），只收整链判定
                # 为 OK 的段；某段坏到 JSON 都解析不了时跳过，段级结论仍在报告
                # 里。strict 分支在进入本方法前已因非 OK 状态整体拒读。
                for index in sorted(ok_segments):
                    try:
                        rows = self._journal.read_segment(index)
                    except StorageError:
                        continue
                    records.extend(row["rec"] for row in rows if isinstance(row, dict) and "rec" in row)
            else:
                if segment not in ok_segments:
                    return {"records": [], "integrity": report, "policy": policy}
                envelopes = self._read_envelopes(segment)
                if isinstance(envelopes, _Malformed):
                    raise IntegrityError(
                        f"审计段 {segment} 读取时解析失败：{envelopes.detail}", component="audit"
                    )
                records.extend(envelope["rec"] for envelope in envelopes)
            return {"records": records, "integrity": report, "policy": policy}

    # ---- 补段：部分失败的修复，幂等、保序 -------------------------------

    def backfill_segment(self, index: int, envelopes: list[dict], source: str = "") -> dict:
        """补一个登记在册的缺失段。

        补入内容必须是该段原始链封套，按链头锚点与登记尾摘要复核通过才
        落盘；不覆盖已有段、不挪动其它段。重复触发同一
        ``(段号, 登记尾摘要)`` 直接返回首次台账结果。
        """

        with self._lock:
            registered = self._segments.get(index)
            if registered is None:
                raise IntegrityError(f"段 {index} 未在链头登记，无法校验来源，拒绝补入", component="audit")
            if index > self.head_segment():
                raise IntegrityError(f"段 {index} 超出当前链尾，不允许预写", component="audit")
            expected_anchor = registered.anchor_digest
            expected_last = registered.last_digest

            # 先验内容再认幂等：即便段已补齐，也必须先证明补入数据能对上登记
            # 的锚点与尾摘要，避免"同尾摘要、不同内容"的重复触发被当成无害重试。
            self._validate_backfill_content(index, envelopes, registered, expected_anchor)
            if envelopes[-1]["h"] != expected_last:
                raise IntegrityError(
                    f"补段 {index} 尾摘要与链头登记不符，依据值 {expected_last[:12]} 对不上",
                    component="audit",
                )

            if self._journal.segment_exists(index):
                for ledger in self._backfills:
                    if (
                        ledger["segment"] == index
                        and ledger["expected_last_digest"] == expected_last
                    ):
                        # 内容已经过完整复核且与首次补入承诺一致，才算幂等重试。
                        return {"result": ledger, "repeated": True}
                raise IntegrityError(
                    f"段 {index} 文件已存在，补段不允许覆盖或重排已有段", component="audit"
                )

            self._journal.write_segment(index, envelopes)
            result = {
                "segment": index,
                "count": len(envelopes),
                "first_seq": int(envelopes[0]["seq"]),
                "last_seq": int(envelopes[-1]["seq"]),
                "source": source,
                "basis_segment": index - 1,  # -1 表示创世锚点（首段）
                "anchor_digest": expected_anchor,
                "expected_last_digest": expected_last,
            }
            self._backfills.append(result)
            self._persist_state()
            return {"result": result, "repeated": False}

    def _validate_backfill_content(
        self,
        index: int,
        envelopes: list[dict],
        registered: _SegmentState,
        anchor: str,
    ) -> None:
        if not envelopes:
            raise IntegrityError(f"补段 {index} 内容为空，拒绝写入", component="audit")
        if not all(isinstance(item, dict) and all(k in item for k in ("seq", "prev", "h", "rec")) for item in envelopes):
            raise IntegrityError(f"补段 {index} 存在缺少链封套字段的行", component="audit")
        if len(envelopes) != registered.count:
            raise IntegrityError(
                f"补段 {index} 条数 {len(envelopes)} 与登记 {registered.count} 不符",
                component="audit",
            )
        prev_digest = anchor
        for position, envelope in enumerate(envelopes):
            wanted_seq = registered.first_seq + position
            if int(envelope["seq"]) != wanted_seq:
                raise IntegrityError(
                    f"补段 {index} 第 {position + 1} 条 seq={envelope['seq']}，应为 {wanted_seq}",
                    component="audit",
                )
            if envelope["prev"] != prev_digest:
                raise IntegrityError(
                    f"补段 {index} seq={envelope['seq']} 锚点断链，依据段 {index - 1} 的校验值对不上",
                    component="audit",
                )
            actual = envelope_digest(envelope, prev_digest)
            if envelope["h"] != actual:
                raise IntegrityError(
                    f"补段 {index} seq={envelope['seq']} 摘要复核失败，内容与原始校验值不一致",
                    component="audit",
                )
            prev_digest = actual
        # 循环已逐条核对首序号、连续性、锚点与尾摘要，无需再重复断言。

    def backfill_ledger(self) -> list[dict]:
        """返回补段台账（幂等判定依据，供审计核对）。"""

        with self._lock:
            return list(self._backfills)

    # ---- 杂项 -----------------------------------------------------------

    def _index_from_path(self, path: str) -> int | None:
        name = os.path.basename(path)
        prefix = f"{self._journal.topic}-"
        if not (name.startswith(prefix) and name.endswith(".jsonl")):
            return None
        stem = name[len(prefix) : -len(".jsonl")]
        return int(stem) if stem.isdigit() else None
