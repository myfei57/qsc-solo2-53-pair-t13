"""审计日志。

``AuditLog`` 是事件总线的全量订阅者：组件只发布事件，日志把它们落成流水并
保留内存副本。控制台读内存副本，跨重启回放读落盘流水；两份数据都来自同一
个 :class:`AuditRecord` 结构，字段口径一致。
"""

from __future__ import annotations

import threading

from ..clock import Clock
from ..eventbus import Event, EventBus
from ..store.journal import JsonlJournal
from .record import AuditRecord
from .report import summarize


class AuditLog:
    """审计流水：内存副本 + 分段落盘。"""

    def __init__(
        self,
        clock: Clock,
        bus: EventBus,
        journal: JsonlJournal,
        memory_limit: int = 4096,
    ) -> None:
        self._clock = clock
        self._journal = journal
        self._entries: list[AuditRecord] = []
        self._memory_limit = max(1, memory_limit)
        self._last_verification: dict | None = None
        self._lock = threading.RLock()
        bus.subscribe("*", self._on_event)

    @property
    def journal(self) -> JsonlJournal:
        return self._journal

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
        """记一条审计流水（内存 + 落盘），返回其字典形式。"""

        with self._lock:
            self._entries.append(record)
            if len(self._entries) > self._memory_limit:
                del self._entries[: len(self._entries) - self._memory_limit]
            self._journal.append(record.as_dict())
            if self._last_verification is not None:
                self._last_verification = {**self._last_verification, "stale": True}
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
        """返回审计汇总计数。"""

        with self._lock:
            entries = list(self._entries)
        report = summarize(entries)
        report["journal_count"] = self._journal.count()
        report["active_segment"] = self._journal.active_segment()
        report["integrity"] = self.integrity_status()
        return report

    def verify_integrity(self, mode: str = "strict", trigger: str = "console") -> dict:
        """固定执行“逐段定位 + 整链判定”，并把结论写入审计。"""

        with self._lock:
            report_before = self._journal.verify_chain()
            self._record_integrity_event(
                "integrity_verified",
                "notice" if report_before["ok"] else "warning",
                "审计分段整链校验通过" if report_before["ok"] else "审计分段整链校验未通过",
                report_before,
                trigger=trigger,
            )
            report = {**self._journal.verify_chain(), "mode": mode, "stale": False}
            self._last_verification = report
            report["audited_conclusion"] = self._compact_report(report_before)
            return report

    def integrity_status(self) -> dict:
        """返回最近一次校验结论；尚未校验时只做只读展示，不产生审计。"""

        with self._lock:
            if self._last_verification is None:
                return {
                    "ok": False,
                    "stale": True,
                    "policy": "segment_independent_check_then_one_chain_verification",
                    "message": "尚未执行整链校验",
                }
            return dict(self._last_verification)

    def replay_all_verified(self, mode: str = "strict") -> tuple[list[dict], dict]:
        """按既定读取策略回放：strict 整链拒读，partial 标记后读已验证段。"""

        with self._lock:
            return self._journal.read_all_verified(mode=mode)

    def replay_segment_verified(self, index: int, mode: str = "strict") -> tuple[list[dict], dict]:
        """先整链判定，再按策略读取单段，避免把坏段当正常数据。"""

        with self._lock:
            return self._journal.read_segment_verified(index, mode=mode)

    def repair_segment(
        self,
        index: int,
        records: list[dict],
        request_id: str | None = None,
        trigger: str = "console",
    ) -> dict:
        """补齐清单证明过的缺失段；重复调用返回同一结果，不覆盖已有段。"""

        with self._lock:
            result = self._journal.repair_segment(index, records, request_id=request_id)
            report_after = self._journal.verify_chain()
            self._record_integrity_event(
                "integrity_segment_repaired",
                "notice" if result["ok"] else "warning",
                f"审计段 {index} 补齐成功" if result["ok"] else f"审计段 {index} 补齐失败",
                {
                    "repair": result,
                    "verification": self._compact_report(report_after),
                    "policy": report_after["policy"],
                },
                trigger=trigger,
            )
            report = self._journal.verify_chain()
            self._last_verification = {**report, "mode": "partial", "stale": True}
            return result

    def _compact_report(self, report: dict) -> dict:
        return {
            "ok": report["ok"],
            "mode": "segment_independent_check_then_one_chain_verification",
            "manifest": report["manifest"],
            "head_segment": report["head_segment"],
            "missing_segments": report["missing_segments"],
            "tampered_segments": report["tampered_segments"],
            "unlinked_segments": report["unlinked_segments"],
            "segments": report["segments"],
        }

    def _record_integrity_event(
        self, action: str, severity: str, message: str, detail: dict, trigger: str
    ) -> None:
        record = AuditRecord.create(
            self._clock.now(),
            "",
            "audit",
            action,
            severity=severity,
            message=message,
            trigger=trigger,
            integrity=self._compact_report(detail)
            if action == "integrity_verified"
            else detail,
        )
        # 直接走底层 append，避免再经过 record() 把刚得到的校验结论标记为 stale。
        self._journal.append(record.as_dict())
        self._entries.append(record)
        if len(self._entries) > self._memory_limit:
            del self._entries[: len(self._entries) - self._memory_limit]

    def to_records(self, raw: list[dict]) -> list[AuditRecord]:
        """把落盘字段还原成记录对象。"""

        return [AuditRecord.from_dict(item) for item in raw]
