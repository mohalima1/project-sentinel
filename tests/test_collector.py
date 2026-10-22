"""Synthetic queue/source fixtures; live collection is verified separately."""

import sqlite3

import pytest


def spool_at(path, **kwargs):
    from sentinel.collector.spool import Spool

    return Spool(path, "synthetic-host", min_free_bytes=0, **kwargs)


def test_baseline_change_restart_and_ack(tmp_path):
    path = tmp_path / "queue.db"
    with spool_at(path) as spool:
        spool.snapshot("services", {"fixture": {"path": "old.exe"}})
        rows = spool.pending()
        assert len(rows) == 1 and rows[0]["category"] == "inventory_baseline"
        assert rows[0]["evidence"]["items"]["fixture"]["path"] == "old.exe"
        spool.ack([rows[0]["identity"]])
    with spool_at(path) as spool:
        spool.snapshot("services", {"fixture": {"path": "new.exe"}})
        change = spool.pending()[0]
        assert change["evidence"]["before"]["path"] == "old.exe"
        assert change["evidence"]["after"]["path"] == "new.exe"
        spool.snapshot("services", {"fixture": {"path": "new.exe"}})
        assert len(spool.pending()) == 1
        spool.ack([change["identity"]])
        assert spool.pending() == []


def test_full_queue_and_disk_failure_do_not_advance_snapshot(tmp_path, monkeypatch):
    from sentinel.collector.spool import QueueFull

    path = tmp_path / "queue.db"
    with spool_at(path, max_queue_bytes=1024) as spool:
        with pytest.raises(QueueFull):
            spool.snapshot("services", {"fixture": {"path": "x" * 2048}})
        assert spool.state("snapshot:services") is None
        assert spool.pending() == []
        spool.snapshot("services", {"fixture": {"path": "old"}})
        for row in spool.pending():
            spool.ack([row["identity"]])
        import sentinel.collector.spool as module

        monkeypatch.setattr(module, "free_bytes", lambda p: -1)
        with pytest.raises(QueueFull, match="disk"):
            spool.snapshot("services", {})
        assert spool.state("snapshot:services")["items"]["fixture"]["path"] == "old"


def xml(record=1, time="2026-10-01T01:02:03.0000000Z"):
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
    <Provider Name="Fixture"/><EventID>1</EventID><Level>4</Level>
    <TimeCreated SystemTime="{time}"/><EventRecordID>{record}</EventRecordID>
    <Channel>System</Channel><Computer>synthetic-host</Computer></System>
    <EventData><Data Name="fixture">Synthetic</Data></EventData></Event>'''


def test_log_cursors_reset_reused_ids_and_rollover_gap(tmp_path):
    with spool_at(tmp_path / "queue.db") as spool:
        spool.log_batch(
            "System", {"oldest": 1, "newest": 2, "anchor": None, "events": [xml(1), xml(2)]}
        )
        cursor = spool.state("log:System")
        assert cursor["record"] == 2
        assert len([e for e in spool.pending() if e["category"] == "windows_event"]) == 2
        spool.log_batch("System", {"oldest": 1, "newest": 2, "anchor": xml(2), "events": []})
        assert spool.state("log:System") == cursor
        # Reader detects record reuse, returns new generation from the start.
        new_xml = xml(1, "2026-10-02T01:02:03Z")
        spool.log_batch(
            "System", {"oldest": 1, "newest": 1, "anchor": None, "reset": True, "events": [new_xml]}
        )
        assert spool.state("log:System")["record"] == 1
        rows = spool.pending()
        assert len([e for e in rows if e["category"] == "windows_event"]) == 3
        assert any(e["category"] == "collection_gap" for e in rows)
        spool.log_batch("System", {"oldest": 8, "newest": 8, "anchor": None, "events": [xml(8)]})
        assert any(e["evidence"].get("missing_from") == 2 for e in spool.pending())


def test_full_queue_preserves_log_cursor_and_sql_failure_rolls_back(tmp_path, monkeypatch):
    from sentinel.collector.spool import QueueFull

    with spool_at(tmp_path / "queue.db", max_queue_bytes=500) as spool:
        with pytest.raises(QueueFull):
            spool.log_batch("System", {"oldest": 1, "newest": 1, "anchor": None, "events": [xml()]})
        assert spool.state("log:System") is None
        assert spool.pending() == []
    with spool_at(tmp_path / "other.db") as spool:

        def fail(*args):
            raise sqlite3.OperationalError("database or disk is full")

        monkeypatch.setattr(spool, "enqueue", fail)
        with pytest.raises(sqlite3.OperationalError):
            spool.snapshot("services", {})
        assert spool.state("snapshot:services") is None


def test_delivery_retries_without_deleting_unacknowledged_events(tmp_path):
    from sentinel.collector.runtime import deliver

    with spool_at(tmp_path / "queue.db") as spool:
        spool.snapshot("services", {})
        pending = spool.pending()

        def offline(payload):
            raise OSError("offline")

        with pytest.raises(OSError):
            deliver(spool, offline, {})
        assert spool.pending() == pending
        # Lost acknowledgement: replay must remain byte-identical.
        received = []

        def success(payload):
            received.extend(payload["events"])
            return {"accepted": [e["identity"] for e in payload["events"]]}

        deliver(spool, success, {})
        assert received == pending and spool.pending() == []


def test_unavailable_source_never_generates_removal(tmp_path):
    from sentinel.collector.runtime import collect_source

    with spool_at(tmp_path / "queue.db") as spool:
        spool.snapshot("services", {"fixture": {"name": "keep"}})
        spool.ack([e["identity"] for e in spool.pending()])
        health = {}

        def denied(source, cursor):
            return {"status": "denied", "error": "Synthetic access denied"}

        collect_source(spool, "services", denied, health)
        assert health["services"]["status"] == "denied"
        assert spool.pending() == []
        assert "fixture" in spool.state("snapshot:services")["items"]


def test_spool_hard_disk_cap_and_host_binding(tmp_path):
    from sentinel.collector.spool import QueueFull, Spool

    path = tmp_path / "queue.db"
    with spool_at(path, max_spool_bytes=131072) as spool:
        with pytest.raises((QueueFull, sqlite3.OperationalError)):
            spool.snapshot("software", {"fixture": {"raw": "x" * 200000}})
        assert spool.state("snapshot:software") is None
    assert path.stat().st_size <= 131072
    with pytest.raises(ValueError, match="host"):
        with Spool(path, "different-host"):
            pass


def test_single_collector_lock_prevents_competing_snapshots(tmp_path):
    from sentinel.collector.lock import collector_lock

    path = tmp_path / "collector.lock"
    with collector_lock(path):
        with pytest.raises(OSError, match="already running"):
            with collector_lock(path):
                pass
    with collector_lock(path):
        pass


def test_empty_log_baseline_and_cumulative_gap_count(tmp_path):
    with spool_at(tmp_path / "queue.db") as spool:
        spool.log_batch("System", {"oldest": 0, "newest": 0, "events": []})
        assert spool.state("log:System")["record"] == 0
        assert spool.state("gap_count") == 1
        spool.ack([e["identity"] for e in spool.pending()])
        assert spool.state("gap_count") == 1
        spool.log_batch("System", {"oldest": 0, "newest": 0, "events": []})
        assert spool.pending() == []


def test_rollover_between_metadata_and_event_read_is_reported(tmp_path):
    with spool_at(tmp_path / "queue.db") as spool:
        spool.log_batch("System", {"oldest": 1, "newest": 1, "events": [xml(1)]})
        spool.ack([e["identity"] for e in spool.pending()])
        spool.log_batch("System", {"oldest": 1, "newest": 10, "events": [xml(8)]})
        gap = next(e for e in spool.pending() if e["category"] == "collection_gap")
        assert gap["evidence"]["missing_from"] == 2
        assert gap["evidence"]["missing_until"] == 7


def test_windows_empty_cursor_does_not_reapply_initial_history_limit():
    import os
    import subprocess
    from pathlib import Path

    from sentinel.collector.windows import __file__ as windows_file

    if os.name != "nt":
        pytest.skip("PowerShell cursor boundary check requires Windows")
    helper = Path(windows_file).with_name("windows_cursor.ps1")
    assert helper.is_file()
    # Fixed production helper only; no log clearing or Windows settings changes.
    script = (
        f". '{str(helper).replace(chr(39), chr(39) * 2)}'; "
        "Get-SentinelStartRecord -After 0 -Newest 600 -HasCursor $true -Reset $false; "
        "Get-SentinelStartRecord -After 0 -Newest 600 -HasCursor $false -Reset $false; "
        "Get-SentinelStartRecord -After 500 -Newest 30 -HasCursor $true -Reset $true"
    )
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["0", "400", "0"]


def test_collection_reports_health_between_each_source(tmp_path):
    from sentinel.collector.runtime import collect_cycle

    sent = []

    def send(payload):
        sent.append(payload["health"]["sources"].copy())
        return {"accepted": [e["identity"] for e in payload["events"]]}

    def reader(source, cursor):
        if source == "tasks":
            assert sent and sent[-1]["services"]["status"] == "available"
        return {"status": "available", "items": {}}

    with spool_at(tmp_path / "queue.db") as spool:
        health = {"sources": {}, "failures": 0}
        collect_cycle(spool, ("services", "tasks"), reader, send, health)
        assert spool.pending() == []
        assert set(sent[-1]) == {"services", "tasks"}
