"""审计日志。

``AuditLog`` 是事件总线的全量订阅者：组件只发布事件，日志把它们落成流水并
保留内存副本。控制台读内存副本，跨重启回放读落盘流水；两份数据都来自同一
个 :class:`AuditRecord` 结构，字段口径一致。

落盘流水不是裸记录，而是经 :class:`~coke.audit.integrity.IntegrityChain` 封
成的跨段哈希链：每条带全局序号、前驱摘要和自摘要，链头状态单独原子落盘。
对外暴露两种读法，按用途选定：

- :meth:`replay_from_journal`（取证/重启回放，strict）——链上任意一段不过
  就整体拒读；
- :meth:`replay_marked`（控制台展示，marked）——完段照常读、问题段标记后
  不给内容，逐段结论随结果一起返回。

校验方式定死为 :meth:`verify_integrity` 的整链一次验；校验结论既返回给控
制台，也作为一条审计流水落盘。补缺失段走 :meth:`backfill_segment`，按链头
登记的校验值复核，保序、不覆盖，重复触发幂等，动作本身同样落审计。
"""

from __future__ import annotations

import os
import threading

from ..clock import Clock
from ..errors import IntegrityError
from ..eventbus import Event, EventBus
from ..ids import IdFactory
from ..store.jsonfile import JsonStore
from ..store.journal import JsonlJournal
from .integrity import STATUS_OK, IntegrityChain
from .record import AuditRecord
from .report import summarize


class AuditLog:
    """审计流水：内存副本 + 分段落盘 + 跨段完整性链。"""

    def __init__(
        self,
        clock: Clock,
        bus: EventBus,
        journal: JsonlJournal,
        ids: IdFactory | None = None,
        memory_limit: int = 4096,
    ) -> None:
        self._clock = clock
        self._journal = journal
        # 链头状态放在 journal 同级的 <topic>-chain/ 下，独立目录原子写，
        # 不混进 JsonStore 的业务文档清单。
        chain_dir = os.path.join(journal.root, f"{journal.topic}-chain")
        self._chain = IntegrityChain(journal, JsonStore(chain_dir))
        self._ids = ids or IdFactory("chk")
        self._entries: list[AuditRecord] = []
        self._memory_limit = max(1, memory_limit)
        self._last_verification: dict | None = None
        self._lock = threading.RLock()
        bus.subscribe("*", self._on_event)

    @property
    def journal(self) -> JsonlJournal:
        return self._journal

    @property
    def chain(self) -> IntegrityChain:
        return self._chain

    def _on_event(self, event: Event) -> None:
        severity = "notice"
        payload = dict(event.payload)
        if "severity" in payload:
            severity = str(payload.pop("severity"))
        oven = str(payload.pop("oven", ""))
        message = str(payload.pop("message", ""))
        self.record(
            AuditRecord.create(
                self._clock.now(), oven, event.component, event.action, severity, message, **payload
            )
        )

    def record(self, record: AuditRecord) -> dict:
        """记一条审计流水（内存 + 链上落盘），返回其字典形式。"""

        with self._lock:
            self._entries.append(record)
            if len(self._entries) > self._memory_limit:
                del self._entries[: len(self._entries) - self._memory_limit]
            self._chain.append(record.as_dict())
        return record.as_dict()

    def entries(self, limit: int = 100) -> list[dict]:
        """返回最近的记录（最新的在前）。"""

        with self._lock:
            selected = list(self._entries)[-limit:]
        return [entry.as_dict() for entry in reversed(selected)]

    def tail(self, limit: int = 20) -> list[dict]:
        """返回最近的记录（按时间升序）。"""

        with self._lock:
            selected = list(self._entries)[-limit:]
        return [entry.as_dict() for entry in selected]

    def alarms(self) -> list[dict]:
        """返回全部告警档记录。"""

        with self._lock:
            selected = [entry for entry in self._entries if entry.is_alarm()]
        return [entry.as_dict() for entry in selected]

    def records(self, limit: int = 200) -> list[AuditRecord]:
        """返回最近的记录对象（按时间升序），供时间线构造使用。"""

        with self._lock:
            return list(self._entries)[-limit:]

    def summary(self) -> dict:
        """返回审计汇总计数与链上状态。"""

        with self._lock:
            entries = list(self._entries)
        report = summarize(entries)
        report["journal_count"] = self._journal.count()
        report["active_segment"] = self._journal.active_segment()
        report["chain"] = {
            "next_seq": self._chain.next_seq,
            "head_segment": self._chain.head_segment(),
            "registered_segments": self._chain.registered_segments(),
        }
        if self._last_verification is not None:
            report["chain"]["last_verification"] = {
                "check_id": self._last_verification["check_id"],
                "status": self._last_verification["status"],
                "ts": self._last_verification["ts"],
                "segments_checked": self._last_verification["segments_checked"],
                "first_fault": self._last_verification["first_fault"],
            }
        return report

    def replay_from_journal(self, limit: int = 100_000, *, segment: int | None = None) -> list[dict]:
        """严格回放：整链一次验，不过即整体拒读（抛 ``IntegrityError``）。

        整链口径不放宽：即便只请求一个前段，只要链上任一段不过，严格读取
        就拒绝——单段自洽证明不了它仍处在一条完整可信的链上。
        """

        outcome = self._chain.replay("strict", segment=segment)
        return outcome["records"][-limit:]

    def replay_marked(self, limit: int = 100_000, *, segment: int | None = None) -> dict:
        """标记回放：整链一次验，只返回完段记录并携带逐段结论。"""

        outcome = self._chain.replay("marked", segment=segment)
        outcome["records"] = outcome["records"][-limit:]
        return outcome

    def replay_segment(self, index: int) -> list[dict]:
        """按段号严格回放一段（该段或其锚点段有问题即拒读）。"""

        return self.replay_from_journal(segment=index)

    def verify_integrity(self, *, triggered_by: str = "manual") -> dict:
        """整链一次验；结论供控制台展示，并作为一条审计流水落盘。

        校验结论本身也写进同一条链：下一次校验必须把这次结论一并验过，
        "谁在什么时候查过、查出什么"同样可追溯。链已损坏到无法追加结论
        时（例如链尾被删），报告仍返回，但 ``audit_recorded`` 标为 False。
        """

        with self._lock:
            check_id = self._ids.next()
            report = self._chain.verify()
            status = report["status"]
            severity = "notice" if status == STATUS_OK else "alarm"
            meta = AuditRecord.create(
                self._clock.now(),
                "",
                "audit",
                "integrity_checked",
                severity=severity,
                message=(
                    f"审计链校验通过（{report['segments_checked']} 段）"
                    if status == STATUS_OK
                    else f"审计链校验未通过：{status}，首个问题段 {report['first_fault']['segment']}"
                ),
                check_id=check_id,
                triggered_by=triggered_by,
                status=status,
                segments_checked=report["segments_checked"],
                first_fault_segment=(
                    report["first_fault"]["segment"] if report["first_fault"] else None
                ),
            )
            recorded = True
            try:
                self.record(meta)
            except IntegrityError:
                # 链尾已断时结论照常返回给控制台，但无法落盘必须显式标记。
                recorded = False
            result = {
                "check_id": check_id,
                "ts": self._clock.now(),
                "triggered_by": triggered_by,
                "audit_recorded": recorded,
                **report,
            }
            self._last_verification = result
            return result

    def backfill_segment(
        self, index: int, envelopes: list[dict], *, source: str = "manual", triggered_by: str = "manual"
    ) -> dict:
        """补一个缺失段（幂等、保序、按登记校验值复核），动作落审计。

        补段属于部分失败的修复：已有段顺序不动，只在空洞处原子补入；
        补完再跑一次整链校验确认修复效果。重复触发同一
        ``(段号, 登记尾摘要)`` 直接返回首次台账，不重复落审计。
        """

        with self._lock:
            outcome = self._chain.backfill_segment(index, envelopes, source=source)
            result, repeated = outcome["result"], outcome["repeated"]
            verification = self._chain.verify()
            if not repeated:
                fill_id = self._ids.next()
                severity = "notice" if verification["status"] == STATUS_OK else "warning"
                meta = AuditRecord.create(
                    self._clock.now(),
                    "",
                    "audit",
                    "segment_backfilled",
                    severity=severity,
                    message=f"补齐审计段 {index}（{result['count']} 条），来源 {source}",
                    fill_id=fill_id,
                    triggered_by=triggered_by,
                    source=source,
                    segment=index,
                    first_seq=result["first_seq"],
                    last_seq=result["last_seq"],
                    basis_segment=result["basis_segment"],
                    anchor_digest=result["anchor_digest"],
                    expected_last_digest=result["expected_last_digest"],
                    verify_status=verification["status"],
                )
                self.record(meta)
                result["fill_id"] = fill_id
            result["repeated"] = repeated
            result["verification"] = {
                "status": verification["status"],
                "first_fault": verification["first_fault"],
                "segments_checked": verification["segments_checked"],
            }
            return result

    def backfill_ledger(self) -> list[dict]:
        """返回补段台账（幂等判定依据，供控制台与审计核对）。"""

        return self._chain.backfill_ledger()

    def raw_journal_scan(self) -> list[dict]:
        """盘上原始行的全量扫描（不过链），供离线取证工具对照，业务勿用。"""

        return self._journal.read_all()

    def to_records(self, raw: list[dict]) -> list[AuditRecord]:
        """把落盘字段还原成记录对象。"""

        return [AuditRecord.from_dict(item) for item in raw]
