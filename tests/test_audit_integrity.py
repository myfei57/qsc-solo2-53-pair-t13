"""审计流水跨段完整性：哈希链、整链校验、拒读/标记读、补段幂等。

校验口径定死为整链一次验：不存在"每段独立验"的正式结论，段级状态只是
整链遍历的定位产物。
"""

from __future__ import annotations

import json
import os

import pytest

from coke.audit.integrity import (
    GENESIS_DIGEST,
    SEGMENT_MISSING,
    SEGMENT_TAMPERED,
    SEGMENT_UNLINKED,
    STATUS_INCOMPLETE,
    STATUS_OK,
    STATUS_TAMPERED,
    record_digest,
)
from coke.audit.log import AuditLog
from coke.audit.record import AuditRecord
from coke.clock import ManualClock
from coke.errors import IntegrityError
from coke.eventbus import EventBus
from coke.store.journal import JsonlJournal


def _build_log(tmp_path, records: int = 7, limit: int = 3) -> tuple[AuditLog, JsonlJournal]:
    journal = JsonlJournal(str(tmp_path / "audit"), "audit", segment_limit=limit)
    log = AuditLog(ManualClock(), EventBus(), journal)
    for index in range(records):
        log.record(
            AuditRecord.create(
                float(index), "oven01", "pusher", "move", "notice", f"m{index}"
            )
        )
    return log, journal


def _raw_segment(journal: JsonlJournal, index: int) -> list[dict]:
    path = journal.segment_path(index)
    with open(path, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _write_raw_segment(journal: JsonlJournal, index: int, envelopes: list[dict]) -> None:
    with open(journal.segment_path(index), "w", encoding="utf-8") as handle:
        for envelope in envelopes:
            handle.write(json.dumps(envelope, ensure_ascii=False) + "\n")


def test_chain_spans_segments_and_verifies(tmp_path):
    log, journal = _build_log(tmp_path)
    assert journal.active_segment() == 2
    report = log.verify_integrity()
    assert report["status"] == STATUS_OK
    assert report["audit_recorded"] is True
    assert report["segments_checked"] == 3
    # 校验结论本身也在链上：再验一次必须把结论记录一并验过。
    again = log.verify_integrity()
    assert again["status"] == STATUS_OK
    assert again["next_seq"] == report["next_seq"] + 1


def test_digest_is_canonical_and_order_sensitive():
    first = record_digest(0, GENESIS_DIGEST, {"a": 1, "b": 2})
    reordered = record_digest(0, GENESIS_DIGEST, {"b": 2, "a": 1})
    assert first == reordered  # 键序不影响摘要
    changed = record_digest(0, GENESIS_DIGEST, {"a": 1, "b": 3})
    assert first != changed
    other_seq = record_digest(1, GENESIS_DIGEST, {"a": 1, "b": 2})
    assert first != other_seq


def test_record_tampering_is_localized_to_segment(tmp_path):
    log, journal = _build_log(tmp_path)
    envelopes = _raw_segment(journal, 1)
    envelopes[0]["rec"]["message"] = "tampered"
    _write_raw_segment(journal, 1, envelopes)

    report = log.verify_integrity()
    assert report["status"] == STATUS_TAMPERED
    fault = report["first_fault"]
    assert fault["segment"] == 1
    assert fault["status"] == SEGMENT_TAMPERED
    assert fault["seq"] == 3  # limit=3：段1首条全局序号为 3


def test_extra_inserted_record_breaks_the_chain(tmp_path):
    log, journal = _build_log(tmp_path)
    envelopes = _raw_segment(journal, 0)
    forged = dict(envelopes[1])
    forged["rec"] = {**forged["rec"], "message": "forged"}
    _write_raw_segment(journal, 0, [envelopes[0], forged, *envelopes[1:]])
    report = log.verify_integrity()
    assert report["status"] == STATUS_TAMPERED
    assert report["first_fault"]["segment"] == 0


def test_missing_segment_is_incomplete_with_location(tmp_path):
    log, journal = _build_log(tmp_path)
    os.remove(journal.segment_path(1))
    report = log.verify_integrity()
    assert report["status"] == STATUS_INCOMPLETE
    assert report["first_fault"]["segment"] == 1
    assert report["first_fault"]["status"] == SEGMENT_MISSING
    statuses = {item["segment"]: item["status"] for item in report["segments"]}
    # 缺口之后的段即便内容没动，也是脱链，不能冒充可信。
    assert statuses[2] == SEGMENT_UNLINKED


def test_strict_replay_rejects_on_any_fault(tmp_path):
    log, journal = _build_log(tmp_path)
    os.remove(journal.segment_path(1))
    with pytest.raises(IntegrityError) as excinfo:
        log.replay_from_journal()
    assert "1" in excinfo.value.message
    with pytest.raises(IntegrityError):
        log.replay_segment(2)  # 脱链段同样拒读


def test_marked_replay_returns_only_trusted_prefix(tmp_path):
    log, journal = _build_log(tmp_path)
    os.remove(journal.segment_path(1))
    outcome = log.replay_marked()
    assert outcome["policy"] == "marked"
    assert outcome["integrity"]["status"] == STATUS_INCOMPLETE
    messages = [row["message"] for row in outcome["records"] if row.get("component") == "pusher"]
    assert messages == ["m0", "m1", "m2"]  # 只有段0可信，段2脱链不给内容


def test_backfill_restores_chain_without_reordering(tmp_path):
    log, journal = _build_log(tmp_path)
    backup = _raw_segment(journal, 1)
    os.remove(journal.segment_path(1))
    result = log.backfill_segment(1, backup, source="offsite-replica")

    assert result["repeated"] is False
    assert result["verification"]["status"] == STATUS_OK
    assert result["basis_segment"] == 0  # 依据上一段的尾摘要
    assert result["anchor_digest"]
    assert result["expected_last_digest"]
    messages = [
        row["message"]
        for row in log.replay_from_journal()
        if row.get("component") == "pusher"
    ]
    assert messages == [f"m{index}" for index in range(7)]  # 时序不被打乱

    ledger = log.backfill_ledger()
    assert len(ledger) == 1 and ledger[0]["source"] == "offsite-replica"
    # 补段后跑一次整链校验，动作与结论都要落审计。
    log.verify_integrity(triggered_by="test")
    actions = [row["action"] for row in log.replay_from_journal()]
    assert "segment_backfilled" in actions
    assert "integrity_checked" in actions


def test_backfill_is_idempotent(tmp_path):
    log, journal = _build_log(tmp_path)
    backup = _raw_segment(journal, 1)
    os.remove(journal.segment_path(1))
    first = log.backfill_segment(1, [dict(item) for item in backup])
    rows_before = journal.count()
    second = log.backfill_segment(1, [dict(item) for item in backup])
    assert second["repeated"] is True
    assert second["fill_id"] == first["fill_id"]
    assert journal.count() == rows_before  # 幂等重试不重复落审计
    assert len(log.backfill_ledger()) == 1


def test_backfill_rejects_content_mismatching_registered_digest(tmp_path):
    log, journal = _build_log(tmp_path)
    backup = _raw_segment(journal, 1)
    os.remove(journal.segment_path(1))
    bad = [dict(item) for item in backup]
    bad[0]["rec"]["message"] = "wrong"
    with pytest.raises(IntegrityError):
        log.backfill_segment(1, bad)
    # 被拒后空洞仍在，且没有留下半成品文件。
    assert not os.path.exists(journal.segment_path(1))
    assert log.verify_integrity()["status"] == STATUS_INCOMPLETE


def test_backfill_never_overwrites_or_presets(tmp_path):
    log, journal = _build_log(tmp_path)
    backup = _raw_segment(journal, 1)
    with pytest.raises(IntegrityError):
        log.backfill_segment(1, backup)  # 段还在：禁止覆盖
    with pytest.raises(IntegrityError):
        log.backfill_segment(99, backup)  # 未登记：禁止预写


def test_append_is_refused_onto_truncated_tail(tmp_path):
    log, journal = _build_log(tmp_path)
    os.remove(journal.segment_path(journal.active_segment()))
    with pytest.raises(IntegrityError):
        log.record(AuditRecord.create(99.0, "oven01", "pusher", "after_truncation"))


def test_chain_survives_restart(tmp_path):
    log, journal = _build_log(tmp_path)
    next_seq = log.chain.next_seq

    restored = AuditLog(ManualClock(), EventBus(), JsonlJournal(journal.root, "audit", segment_limit=3))
    assert restored.chain.next_seq == next_seq
    restored.record(AuditRecord.create(7.0, "oven01", "pusher", "after_restart"))
    assert len(restored.replay_from_journal()) == 7 + 1
    # 校验结论再追加一条，下一次回放必须把它包含在内且仍然整链通过。
    assert restored.verify_integrity()["status"] == STATUS_OK
    assert len(restored.replay_from_journal()) == 7 + 2


def test_verification_is_logged_with_alarm_severity_on_failure(tmp_path):
    log, journal = _build_log(tmp_path)
    os.remove(journal.segment_path(1))
    report = log.verify_integrity(triggered_by="test")
    assert report["status"] == STATUS_INCOMPLETE
    # 链尾完好时，失败结论也要落审计（alarm 档）。
    alarms = [entry for entry in log.entries(limit=50) if entry["action"] == "integrity_checked"]
    assert alarms and alarms[0]["severity"] == "alarm"
