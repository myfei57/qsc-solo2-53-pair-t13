"""分段 JSONL 流水日志。

流水只追加不重写，按 ``segment_limit`` 条一段滚动成 ``<topic>-00000.jsonl``、
``<topic>-00001.jsonl`` …。每段有同名 ``.sig`` 元数据封套，段内记录摘要按
顺序滚动，下一段又引用上一段签名封套摘要；另外由签名清单固定链头，因此删段、
多写、改一条或调整记录顺序都会在整链校验中暴露，逐段结果负责定位问题段。
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from typing import Any

from ..errors import StorageError
from .integrity import (
    GENESIS_DIGEST,
    canonical_json,
    envelope_digest,
    load_secret,
    open_envelope,
    records_digest,
    sha256_hex,
    sign_envelope,
)


class JsonlJournal:
    """按段落写入、带跨段哈希链的 JSONL 流水。"""

    def __init__(self, root: str, topic: str, segment_limit: int = 512) -> None:
        self._root = os.path.abspath(root)
        self._topic = topic
        self._segment_limit = max(1, segment_limit)
        self._lock = threading.RLock()
        os.makedirs(self._root, exist_ok=True)
        try:
            self._secret = load_secret(self._root)
        except (OSError, ValueError) as error:
            raise StorageError(f"加载审计完整性密钥失败: {error}", component="store") from error
        self._manifest_path = os.path.join(self._root, f"{self._topic}-integrity.json")
        self._repair_dir = os.path.join(self._root, f".{self._topic}-repairs")
        os.makedirs(self._repair_dir, exist_ok=True)
        if os.path.isfile(self._manifest_path):
            self._manifest, self._manifest_envelope, issues = self._read_signed_json(self._manifest_path)
            if issues or not self._manifest_valid_locked(self._manifest, self._manifest_envelope):
                raise StorageError("审计完整性清单校验失败，禁止继续追加流水", component="store")
        else:
            self._manifest, self._manifest_envelope = self._bootstrap_locked()

    @property
    def topic(self) -> str:
        return self._topic

    def _segment_path(self, index: int) -> str:
        return os.path.join(self._root, f"{self._topic}-{index:05d}.jsonl")

    def _sidecar_path(self, index: int) -> str:
        return self._segment_path(index) + ".sig"

    def _repair_path(self, request_id: str) -> str:
        digest = sha256_hex(request_id.encode("utf-8"))
        return os.path.join(self._repair_dir, f"{digest}.json")

    def _discover_indexes_locked(self, suffix: str) -> list[int]:
        pattern = re.compile(rf"^{re.escape(self._topic)}-(\d+)\.jsonl{re.escape(suffix)}$")
        found: list[int] = []
        for name in os.listdir(self._root):
            match = pattern.match(name)
            if match:
                found.append(int(match.group(1)))
        return sorted(found)

    def _read_signed_json(self, path: str) -> tuple[dict | None, dict | None, list[str]]:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                signed = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return None, None, ["unreadable"]
        body, issues = open_envelope(self._secret, signed)
        if not isinstance(body, dict):
            return None, signed if isinstance(signed, dict) else None, issues or ["not_object"]
        return body, signed if isinstance(signed, dict) else None, issues

    def _read_jsonl_file_locked(self, path: str) -> tuple[list[dict] | None, bool]:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                records = [json.loads(line) for line in handle if line.strip()]
        except (OSError, json.JSONDecodeError):
            return None, True
        return records, False

    def _atomic_write_json_locked(self, path: str, payload: Any) -> None:
        directory = os.path.dirname(path)
        try:
            handle = tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=directory, prefix=".audit-tmp-", suffix=".tmp", delete=False
            )
            with handle:
                json.dump(payload, handle, ensure_ascii=False, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(handle.name, path)
        except OSError as error:
            raise StorageError(f"写入完整性文件失败: {error}", component="store") from error

    def _atomic_write_jsonl_locked(self, path: str, records: list[Any]) -> None:
        directory = os.path.dirname(path)
        try:
            handle = tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=directory, prefix=".audit-tmp-", suffix=".tmp", delete=False
            )
            with handle:
                for record in records:
                    handle.write(canonical_json(record) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(handle.name, path)
        except OSError as error:
            raise StorageError(f"写入流水段失败: {error}", component="store") from error

    def _write_manifest_locked(self, manifest: dict) -> None:
        signed = sign_envelope(self._secret, manifest)
        self._atomic_write_json_locked(self._manifest_path, signed)
        self._manifest = manifest
        self._manifest_envelope = signed

    def _bootstrap_locked(self) -> tuple[dict, dict]:
        """首次启用完整性时，为既有段补签名并建立链头。"""

        indexes = self._discover_indexes_locked("")
        expected_index = 0
        expected_prev = GENESIS_DIGEST
        start_seq = 0
        entries: list[dict] = []
        for index in indexes:
            if index != expected_index:
                raise StorageError(f"审计段 {expected_index} 缺失，无法建立完整性链", component="store")
            path = self._segment_path(index)
            records, read_failed = self._read_jsonl_file_locked(path)
            if read_failed or records is None:
                raise StorageError(f"审计段 {index} 不可读，无法建立完整性链", component="store")
            body = self._build_sidecar_body_locked(index, start_seq, records, expected_prev, False, True)
            sidecar_path = self._sidecar_path(index)
            if os.path.isfile(sidecar_path):
                existing, _, issues = self._read_signed_json(sidecar_path)
                if issues or existing != body:
                    raise StorageError(f"审计段 {index} 元数据与流水不一致", component="store")
                signed = existing
            else:
                signed = sign_envelope(self._secret, body)
                self._atomic_write_json_locked(sidecar_path, signed)
            entries.append({**body, "envelope_digest": envelope_digest(signed)})
            expected_prev = envelope_digest(signed)
            start_seq += len(records)
            expected_index += 1
        manifest = {
            "version": 1,
            "algorithm": "HMAC-SHA256",
            "chain_policy": "segment_locate_then_chain_decide",
            "head_segment": indexes[-1] if indexes else None,
            "segments": entries,
        }
        signed_manifest = sign_envelope(self._secret, manifest)
        self._atomic_write_json_locked(self._manifest_path, signed_manifest)
        return manifest, signed_manifest

    def _build_sidecar_body_locked(
        self,
        index: int,
        start_seq: int,
        records: list[Any],
        previous_envelope: str,
        sealed: bool,
        onboarded: bool = False,
    ) -> dict:
        timestamps = [float(item.get("ts", 0.0)) for item in records if isinstance(item, dict)]
        return {
            "version": 1,
            "segment": index,
            "start_seq": start_seq,
            "end_seq": start_seq + len(records) - 1,
            "count": len(records),
            "first_ts": min(timestamps) if timestamps else None,
            "last_ts": max(timestamps) if timestamps else None,
            "records_digest": records_digest(self._secret, records),
            "prev_envelope_digest": previous_envelope,
            "sealed": sealed,
            "onboarded": onboarded,
        }

    def _manifest_entry_locked(self, index: int) -> dict | None:
        for entry in self._manifest.get("segments", []):
            if isinstance(entry, dict) and entry.get("segment") == index:
                return entry
        return None

    def _manifest_valid_locked(self, manifest: Any, signed: Any) -> bool:
        if not isinstance(manifest, dict) or not isinstance(signed, dict):
            return False
        if manifest.get("version") != 1 or manifest.get("algorithm") != "HMAC-SHA256":
            return False
        entries = manifest.get("segments")
        if not isinstance(entries, list):
            return False
        previous_end = -1
        for position, entry in enumerate(entries):
            if not isinstance(entry, dict) or entry.get("segment") != position:
                return False
            if int(entry.get("start_seq", -1)) != previous_end + 1:
                return False
            count = entry.get("count")
            if not isinstance(count, int) or count < 1 or int(entry.get("end_seq", -1)) != previous_end + count:
                return False
            previous_end = int(entry["end_seq"])
            if not isinstance(entry.get("envelope_digest"), str):
                return False
        head = manifest.get("head_segment")
        if entries:
            return head == entries[-1].get("segment")
        return head is None

    def _assert_manifest_fresh_locked(self) -> None:
        if not os.path.isfile(self._manifest_path):
            raise StorageError("审计完整性清单缺失，禁止追加", component="store")
        body, _, issues = self._read_signed_json(self._manifest_path)
        if issues or canonical_json(body) != canonical_json(self._manifest):
            raise StorageError("审计完整性清单已被改动，禁止追加", component="store")

    def append(self, record: Any) -> str:
        """追加一条记录，返回写入的段路径。"""

        with self._lock:
            self._assert_manifest_fresh_locked()
            head = self._manifest.get("head_segment")
            if head is None:
                index = 0
                previous_envelope = GENESIS_DIGEST
                start_seq = 0
                existing: list[Any] = []
            else:
                head_entry = self._manifest_entry_locked(int(head))
                if head_entry is None:
                    raise StorageError("审计完整性清单链头缺失", component="store")
                if head_entry.get("sealed") is True:
                    index = int(head) + 1
                    previous_envelope = str(head_entry["envelope_digest"])
                    start_seq = int(head_entry["end_seq"]) + 1
                    existing = []
                else:
                    index = int(head)
                    previous_envelope = str(head_entry["prev_envelope_digest"])
                    start_seq = int(head_entry["start_seq"])
                    existing, read_failed = self._read_jsonl_file_locked(self._segment_path(index))
                    if read_failed or existing is None:
                        raise StorageError(f"审计活动段 {index} 不可读，禁止追加", component="store")
                    if len(existing) != int(head_entry.get("count", -1)):
                        raise StorageError(f"审计活动段 {index} 条数与清单不一致", component="store")

            if index > len(self._manifest.get("segments", [])):
                raise StorageError(f"审计段 {index} 之前仍有缺口，禁止追加", component="store")
            if index < len(self._manifest.get("segments", [])) and not os.path.isfile(self._segment_path(index)):
                raise StorageError(f"审计段 {index} 已缺失，禁止追加", component="store")

            path = self._segment_path(index)
            try:
                with open(path, "a", encoding="utf-8") as handle:
                    handle.write(canonical_json(record) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as error:
                raise StorageError(f"追加流水失败: {error}", component="store") from error

            records = [*existing, record]
            sealed = len(records) >= self._segment_limit
            body = self._build_sidecar_body_locked(index, start_seq, records, previous_envelope, sealed)
            sidecar = sign_envelope(self._secret, body)
            self._atomic_write_json_locked(self._sidecar_path(index), sidecar)

            entry = {**body, "envelope_digest": envelope_digest(sidecar)}
            entries = list(self._manifest.get("segments", []))
            if index == len(entries):
                entries.append(entry)
            else:
                entries[index] = entry
            manifest = {**self._manifest, "head_segment": index, "segments": entries}
            self._write_manifest_locked(manifest)
            return path

    def segments(self) -> list[str]:
        """返回已存在的段文件路径（按段号升序）。"""

        with self._lock:
            return [self._segment_path(index) for index in self._discover_indexes_locked("")]

    def read_segment_verified(self, index: int, mode: str = "strict") -> tuple[list[dict], dict]:
        """先执行固定的逐段定位/整链判定，再按策略读取指定段。"""

        with self._lock:
            report = self.verify_chain_locked()
            result = report["segments"].get(str(index))
            if result is None:
                raise StorageError(f"审计段 {index} 不在完整性清单中", component="store")
            if result["status"] != "verified":
                if mode == "strict":
                    raise StorageError(
                        f"审计段 {index} 完整性校验失败: {', '.join(result['issues'])}",
                        component="store",
                    )
                return [], report
            records, failed = self._read_jsonl_file_locked(self._segment_path(index))
            if failed or records is None:
                raise StorageError(f"审计段 {index} 校验通过后读取失败", component="store")
            return records, report

    def read_all_verified(self, mode: str = "strict") -> tuple[list[dict], dict]:
        """按逻辑段号读取；strict 任一问题即拒读，partial 只返回已验证段。"""

        with self._lock:
            report = self.verify_chain_locked()
            if mode == "strict" and not report["ok"]:
                raise StorageError("审计整链校验失败，拒绝回放", component="store")
            records: list[dict] = []
            entries = self._manifest.get("segments", []) if report["manifest_ok"] else []
            for entry in entries:
                index = int(entry["segment"])
                result = report["segments"].get(str(index), {})
                if result.get("status") != "verified":
                    continue
                rows, failed = self._read_jsonl_file_locked(self._segment_path(index))
                if failed:
                    continue
                records.extend(rows or [])
            return records, report

    def count(self) -> int:
        """返回清单确认的累计逻辑条数。"""

        with self._lock:
            entries = self._manifest.get("segments", [])
            if not entries:
                return 0
            return int(entries[-1]["end_seq"]) + 1

    def active_segment(self) -> int:
        """返回当前正在写入的段号。"""

        with self._lock:
            head = self._manifest.get("head_segment")
            return 0 if head is None else int(head)

    def verify_chain(self) -> dict:
        """执行整链校验；逐段结果用于定位，最终结论以整链为准。"""

        with self._lock:
            return self.verify_chain_locked()

    def verify_chain_locked(self) -> dict:
        manifest_body, _, manifest_issues = self._read_signed_json(self._manifest_path)
        manifest_ok = not manifest_issues and self._manifest_valid_locked(manifest_body, {})
        disk_manifest_ok = manifest_ok and canonical_json(manifest_body) == canonical_json(self._manifest)
        entries = manifest_body.get("segments", []) if manifest_ok and isinstance(manifest_body, dict) else []
        present = set(self._discover_indexes_locked(""))
        listed = {int(item["segment"]) for item in entries}
        maximum = max(present | listed, default=-1)

        results: dict[str, dict] = {}
        for index in range(maximum + 1):
            issues: list[str] = []
            path = self._segment_path(index)
            sidecar_path = self._sidecar_path(index)
            records: list[Any] | None = None
            body: dict | None = None
            signed: dict | None = None
            sidecar_issues: list[str] = []
            entry = next((item for item in entries if int(item.get("segment", -1)) == index), None)
            records_exist = os.path.isfile(path)

            if records_exist:
                records, read_failed = self._read_jsonl_file_locked(path)
                if read_failed:
                    issues.append("records_unreadable")
            else:
                issues.append("records_missing")

            if os.path.isfile(sidecar_path):
                body, signed, sidecar_issues = self._read_signed_json(sidecar_path)
                issues.extend(sidecar_issues)
            else:
                issues.append("sidecar_missing")

            if entry is None:
                issues.append("not_in_manifest")
            elif disk_manifest_ok and signed is not None:
                if entry.get("envelope_digest") != envelope_digest(signed):
                    issues.append("manifest_envelope_digest_mismatch")

            if records is not None and body is not None and entry is not None and disk_manifest_ok and not sidecar_issues:
                expected_prev = (
                    GENESIS_DIGEST if index == 0 else str(entries[index - 1]["envelope_digest"])
                )
                expected_start = 0 if index == 0 else int(entries[index - 1]["end_seq"]) + 1
                actual_count = len(records)
                expected_body = {key: value for key, value in entry.items() if key != "envelope_digest"}
                if canonical_json(body) != canonical_json(expected_body):
                    issues.append("manifest_entry_mismatch")
                if body.get("segment") != index:
                    issues.append("segment_index_mismatch")
                if body.get("start_seq") != expected_start:
                    issues.append("sequence_gap")
                if body.get("count") != actual_count or int(body.get("end_seq", -1)) != expected_start + actual_count - 1:
                    issues.append("count_mismatch")
                if body.get("records_digest") != records_digest(self._secret, records):
                    issues.append("records_digest_mismatch")
                if body.get("prev_envelope_digest") != expected_prev:
                    issues.append("prev_envelope_digest_mismatch")
                try:
                    timestamps = [float(item.get("ts", 0.0)) for item in records if isinstance(item, dict)]
                except (TypeError, ValueError):
                    issues.append("timestamp_range_mismatch")
                    timestamps = []
                if timestamps and (body.get("first_ts") != min(timestamps) or body.get("last_ts") != max(timestamps)):
                    issues.append("timestamp_range_mismatch")
                expected_sealed = bool(entry.get("sealed"))
                if body.get("sealed") is not expected_sealed:
                    issues.append("sealed_state_mismatch")

            if entry is not None and not records_exist:
                status = "missing"
            elif entry is None and records_exist:
                status = "unlinked"
            elif not issues and body is not None and signed is not None:
                status = "verified"
            else:
                status = "tampered"

            results[str(index)] = {
                "segment": index,
                "status": status,
                "issues": issues,
                "start_seq": body.get("start_seq") if isinstance(body, dict) else None,
                "end_seq": body.get("end_seq") if isinstance(body, dict) else None,
                "records_digest": body.get("records_digest") if isinstance(body, dict) else None,
                "prev_envelope_digest": body.get("prev_envelope_digest") if isinstance(body, dict) else None,
            }

        manifest_status = "verified"
        manifest_issue: list[str] = []
        if manifest_issues:
            manifest_status = "tampered"
            manifest_issue = manifest_issues[:]
        elif not disk_manifest_ok:
            manifest_status = "stale"
            manifest_issue = ["manifest_changed_on_disk"]
        ok = manifest_status == "verified" and all(item["status"] == "verified" for item in results.values())
        return {
            "ok": ok,
            "policy": "segment_independent_check_then_one_chain_verification",
            "manifest_ok": manifest_status == "verified",
            "manifest": {"status": manifest_status, "issues": manifest_issue},
            "head_segment": manifest_body.get("head_segment") if isinstance(manifest_body, dict) else None,
            "segments": results,
            "missing_segments": [int(key) for key, item in results.items() if item["status"] == "missing"],
            "tampered_segments": [int(key) for key, item in results.items() if item["status"] == "tampered"],
            "unlinked_segments": [int(key) for key, item in results.items() if item["status"] == "unlinked"],
        }

    def repair_segment(self, index: int, records: list[dict], request_id: str | None = None) -> dict:
        """按清单补齐一个缺失段；重复请求幂等，已有段不覆盖、不重排。"""

        with self._lock:
            if not isinstance(index, int) or index < 0:
                raise StorageError("补齐段号必须是非负整数", component="store")
            if not isinstance(records, list) or not records:
                raise StorageError("补齐段必须携带至少一条记录", component="store")
            candidate_digest = records_digest(self._secret, records)
            request_key = request_id or f"segment:{index}:{candidate_digest}"
            repair_path = self._repair_path(request_key)
            if os.path.isfile(repair_path):
                stored, _, issues = self._read_signed_json(repair_path)
                if issues or not isinstance(stored, dict):
                    raise StorageError("补齐幂等记录校验失败", component="store")
                if stored.get("records_digest") != candidate_digest:
                    raise StorageError("相同补齐请求编号对应了不同内容", component="store")
                return {**stored.get("result", {}), "idempotent_replay": True}

            report_before = self.verify_chain_locked()
            entry = self._manifest_entry_locked(index)
            outcome = "failed"
            reasons: list[str] = []
            sidecar_source = "not_needed"
            path = self._segment_path(index)

            if not report_before["manifest_ok"]:
                reasons.append("manifest_not_verified")
            if entry is None:
                reasons.append("segment_not_attested_by_manifest")
            if os.path.isfile(path):
                current = report_before["segments"].get(str(index), {})
                if current.get("status") == "verified":
                    outcome = "already_verified"
                    reasons.append("segment_already_present")
                else:
                    reasons.append("existing_segment_not_verified_refusing_overwrite")
            if entry is not None and outcome == "failed" and not os.path.isfile(path):
                entries = self._manifest.get("segments", [])
                expected_prev = (
                    GENESIS_DIGEST if index == 0 else str(entries[index - 1]["envelope_digest"])
                )
                if index > 0 and self._manifest_entry_locked(index - 1) is None:
                    reasons.append("segment_position_not_anchored")
                if entry.get("prev_envelope_digest") != expected_prev:
                    reasons.append("segment_order_mismatch")
                if entry.get("records_digest") != candidate_digest:
                    reasons.append("candidate_records_digest_mismatch")
                if int(entry.get("count", -1)) != len(records):
                    reasons.append("candidate_count_mismatch")
                if not reasons:
                    body = {key: value for key, value in entry.items() if key != "envelope_digest"}
                    sidecar_path = self._sidecar_path(index)
                    if os.path.isfile(sidecar_path):
                        existing_body, existing_signed, sidecar_issues = self._read_signed_json(sidecar_path)
                        if (
                            sidecar_issues
                            or not isinstance(existing_signed, dict)
                            or existing_body != body
                            or envelope_digest(existing_signed) != entry["envelope_digest"]
                        ):
                            reasons.append("existing_sidecar_tampered")
                        else:
                            sidecar_source = "existing_sidecar"
                    else:
                        signed = sign_envelope(self._secret, body)
                        if envelope_digest(signed) != entry["envelope_digest"]:
                            reasons.append("cannot_regenerate_expected_sidecar")
                        else:
                            self._atomic_write_json_locked(sidecar_path, signed)
                            sidecar_source = "regenerated_from_manifest"
                    if not reasons:
                        self._atomic_write_jsonl_locked(path, records)
                        outcome = "filled"

            report_after = self.verify_chain_locked() if outcome == "filled" else report_before
            result_payload = {
                "segment": index,
                "outcome": outcome,
                "ok": outcome in ("filled", "already_verified"),
                "reasons": reasons,
                "sidecar_source": sidecar_source,
                "basis": {
                    "manifest_segment": entry,
                    "candidate_records": records,
                    "candidate_records_digest": candidate_digest,
                    "prev_envelope_digest": entry.get("prev_envelope_digest") if entry else None,
                },
                "verification_before": self._compact_report_locked(report_before),
                "verification_after": self._compact_report_locked(report_after),
            }
            record_envelope = sign_envelope(
                self._secret,
                {
                    "request_id": request_key,
                    "segment": index,
                    "records_digest": candidate_digest,
                    "result": result_payload,
                },
            )
            self._atomic_write_json_locked(repair_path, record_envelope)
            return result_payload

    def _compact_report_locked(self, report: dict) -> dict:
        return {
            "ok": report["ok"],
            "head_segment": report["head_segment"],
            "missing_segments": report["missing_segments"],
            "tampered_segments": report["tampered_segments"],
            "unlinked_segments": report["unlinked_segments"],
        }
