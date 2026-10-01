"""审计留存与死代码门禁。"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from coke.errors import AlignmentError, StorageError
from coke.store.journal import JsonlJournal

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_operations_are_captured_in_audit(platform):
    platform.start()
    platform.charge(oven="oven01", hopper_target_mm=0.0, hopper_measured_mm=0.0)
    entries = platform.audit.entries(limit=10)
    assert entries
    assert any(item["action"] == "charge_complete" for item in entries)
    assert platform.audit.tail(3)[0]["ts"] <= platform.audit.tail(3)[-1]["ts"]
    assert platform.audit.summary()["journal_count"] > 0
    replayed, verification = platform.audit.replay_segment_verified(0)
    assert replayed
    assert verification["ok"] is True


def test_interlock_rejection_is_recorded_as_alarm(platform):
    platform.start()
    rejected = platform.push(oven="oven01", guide_target_mm=0.0, guide_measured_mm=80.0)
    assert rejected["ok"] is False
    assert "guide_not_aligned" in rejected["violations"]
    alarms = platform.audit.alarms()
    assert any(item["action"] == "interlock_rejected" for item in alarms)


def test_platform_error_is_recorded_with_component(platform):
    try:
        platform.guide.lock_apron()
    except AlignmentError as error:
        record = platform.note_error(error)
    assert record["component"] == "guide"
    assert record["action"] == "error"
    assert record["severity"] == "warning"


def test_events_are_published_to_subscribers(platform):
    seen: list[str] = []
    unsubscribe = platform.bus.subscribe("pusher", lambda event: seen.append(event.action))
    platform.push(oven="oven01", guide_target_mm=0.0, guide_measured_mm=0.0, stroke_target_mm=3200.0)
    assert "extend" in seen and "retract" in seen
    unsubscribe()
    assert platform.bus.history("pusher")

def test_segment_hash_chain_locates_tampered_record(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    journal.append({"ts": 1.0, "action": "one"})
    journal.append({"ts": 2.0, "action": "two"})
    path = journal.segments()[0]
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"ts": 3.0, "action": "extra"}, ensure_ascii=False) + "\n")

    report = journal.verify_chain()
    assert report["ok"] is False
    assert report["policy"] == "segment_independent_check_then_one_chain_verification"
    assert report["tampered_segments"] == [0]
    assert "records_digest_mismatch" in report["segments"]["0"]["issues"]
    try:
        journal.read_segment_verified(0, mode="strict")
    except StorageError as error:
        assert "完整性校验失败" in error.message
    else:
        raise AssertionError("strict 模式必须拒读坏段")
    records, partial_report = journal.read_all_verified(mode="partial")
    assert partial_report["ok"] is False
    assert records == []


def test_deleted_segment_can_be_repaired_once_in_logical_order(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=1)
    journal.append({"ts": 1.0, "action": "one"})
    journal.append({"ts": 2.0, "action": "two"})
    missing_path = journal.segments()[0]
    with open(missing_path, "r", encoding="utf-8") as handle:
        missing_records = [json.loads(line) for line in handle if line.strip()]
    os.remove(missing_path)
    assert journal.verify_chain()["missing_segments"] == [0]
    partial_records, partial_report = journal.read_all_verified(mode="partial")
    assert partial_report["ok"] is False
    assert [item["action"] for item in partial_records] == ["two"]

    first = journal.repair_segment(0, missing_records, request_id="repair-1")
    second = journal.repair_segment(0, missing_records, request_id="repair-1")
    assert first["outcome"] == "filled"
    assert second["idempotent_replay"] is True
    report = journal.verify_chain()
    assert report["ok"] is True
    assert report["segments"]["0"]["status"] == "verified"
    assert report["segments"]["1"]["status"] == "verified"


def test_record_reordering_is_tampering(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=3)
    journal.append({"ts": 1.0, "action": "one"})
    journal.append({"ts": 2.0, "action": "two"})
    path = journal.segments()[0]
    with open(path, "r", encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle]
    with open(path, "w", encoding="utf-8") as handle:
        for record in reversed(records):
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    report = journal.verify_chain()
    assert report["ok"] is False
    assert "records_digest_mismatch" in report["segments"]["0"]["issues"]


def test_console_verification_is_displayed_and_audited(platform):
    platform.start()
    platform.charge(oven="oven01", hopper_target_mm=0.0, hopper_measured_mm=0.0)
    from coke.console.api import Api

    api = Api(platform)
    status, payload = api.handle("POST", "/api/audit/verify", {}, {"mode": "strict"})
    assert status == 200
    assert payload["integrity"]["ok"] is True
    status, shown = api.handle("GET", "/api/audit/integrity", {}, {})
    assert status == 200
    assert shown["integrity"]["policy"] == "segment_independent_check_then_one_chain_verification"
    assert any(item["action"] == "integrity_verified" for item in platform.audit.entries(limit=50))

def test_console_repair_is_idempotent_and_audited(platform):
    platform.start()
    platform.charge(oven="oven01", hopper_target_mm=0.0, hopper_measured_mm=0)
    from coke.console.api import Api

    journal = platform.audit.journal
    path = journal.segments()[0]
    with open(path, "r", encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    os.remove(path)
    api = Api(platform)
    body = {"segment": 0, "records": records, "request_id": "console-repair"}
    status, first = api.handle("POST", "/api/audit/repair-segment", {}, body)
    status, second = api.handle("POST", "/api/audit/repair-segment", {}, body)
    assert status == 200
    assert first["repair"]["outcome"] == "filled"
    assert second["repair"]["idempotent_replay"] is True
    assert any(item["action"] == "integrity_segment_repaired" for item in platform.audit.entries(limit=50))


def test_deadcode_gate_reports_no_unused_symbols():
    result = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tools", "deadcode.py"), os.path.join(ROOT, "coke")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert '"unused_symbols": []' in result.stdout
    assert '"unreachable_modules": []' in result.stdout
