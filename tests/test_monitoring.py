"""Synthetic integration fixtures; these do not establish live Windows coverage."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sentinel.app import create_app
from sentinel.local_access import LocalAccess


@pytest.fixture
def monitoring(settings):
    credential = {"host_id": "synthetic-host", "token": "synthetic-ingestion-token-" + "x" * 32}
    (settings.database_path.parent / "ingestion.json").write_text(json.dumps(credential))
    access = LocalAccess()
    with TestClient(create_app(settings, local_access=access), base_url="http://localhost") as c:
        session = c.post("/api/auth/local", json={"token": access.token}).json()
        yield c, credential, session


def event(key="a", **changes):
    return {
        "identity": key * 64,
        "observed_at": datetime.now(UTC).isoformat(),
        "source": "System",
        "category": "windows_event",
        "severity": "info",
        "summary": "Synthetic Windows fixture",
        "evidence": {
            "xml": "<Event>Synthetic fixture</Event>",
            "provider": "Fixture",
            "event_id": 1,
        },
        **changes,
    }


def ingest(c, credential, events, health=None):
    return c.post(
        "/api/ingest",
        json={"host_id": credential["host_id"], "events": events, "health": health or {}},
        headers={"Authorization": "Bearer " + credential["token"]},
    )


def test_ingestion_independent_auth_and_restart_dedup(monitoring, settings):
    c, credential, _ = monitoring
    payload = event()
    assert c.post("/api/ingest", json={}).status_code == 401
    wrong = {**credential, "token": "wrong"}
    assert ingest(c, wrong, [payload]).status_code == 401
    assert ingest(c, {**credential, "host_id": "other-host"}, [payload]).status_code == 403
    assert ingest(c, credential, [payload]).json()["inserted"] == 1
    assert ingest(c, credential, [payload]).json()["inserted"] == 0
    with TestClient(create_app(settings), base_url="http://localhost") as restarted:
        assert ingest(restarted, credential, [payload]).json()["inserted"] == 0
        assert restarted.get("/api/events").status_code == 401
    rows = c.get("/api/events").json()["events"]
    assert len(rows) == 1
    assert (
        c.get(f"/api/events/{rows[0]['id']}").json()["evidence"]["xml"]
        == payload["evidence"]["xml"]
    )


def test_paginated_filters_and_validation(monitoring):
    c, credential, _ = monitoring
    assert (
        ingest(c, credential, [event("a"), event("b", severity="high"), event("c")]).status_code
        == 200
    )
    page = c.get("/api/events?limit=2").json()
    assert len(page["events"]) == 2 and page["next_cursor"]
    page2 = c.get(f"/api/events?limit=2&before={page['next_cursor']}").json()
    assert len(page2["events"]) == 1
    assert c.get("/api/events?source=Security").json()["events"] == []
    assert len(c.get("/api/events?severity=high&category=windows_event").json()["events"]) == 1
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    assert c.get("/api/events", params={"since": future}).json()["events"] == []
    assert c.get("/api/events?q=does-not-exist").json()["events"] == []
    assert c.get("/api/events?limit=999999").status_code == 422
    assert ingest(c, credential, [event("d", observed_at="2026-01-01T00:00:00")]).status_code == 422
    assert ingest(c, credential, [event("d", severity="secure")]).status_code == 422


def test_health_never_implies_security_and_settings_csrf(monitoring):
    c, credential, session = monitoring
    assert c.get("/api/collection").json()["connection"] == "never_connected"
    health = {"sources": {"Security": {"status": "denied"}}, "queue_bytes": 17, "failures": 2}
    assert ingest(c, credential, [], health).status_code == 200
    result = c.get("/api/collection").json()
    assert result["connection"] == "connected" and result["health"] == health
    assert result["last_ingestion"] is None  # Heartbeat alone is not evidence ingestion.
    assert ingest(c, credential, [event()], health).status_code == 200
    assert c.get("/api/collection").json()["last_ingestion"]
    assert c.put("/api/settings", json={"retention_days": 7}).status_code == 403
    assert (
        c.put(
            "/api/settings",
            json={"retention_days": 7},
            headers={"X-CSRF-Token": session["csrf_token"]},
        ).status_code
        == 200
    )
    assert c.get("/api/settings").json()["retention_days"] == 7
    assert c.get("/api/audit").json()["events"][0]["action"] == "settings_changed"


def test_retention_and_capacity_reject_without_partial_commit(monitoring, monkeypatch):
    c, credential, _ = monitoring
    old = event("e", observed_at=(datetime.now(UTC) - timedelta(days=40)).isoformat())
    assert ingest(c, credential, [old, event()]).status_code == 200
    assert len(c.get("/api/events").json()["events"]) == 1
    import sentinel.monitoring.storage as storage

    monkeypatch.setattr(storage, "available_bytes", lambda path: 0)
    rejected = ingest(c, credential, [event("f")])
    assert rejected.status_code == 507
    assert len(c.get("/api/events").json()["events"]) == 1


def test_parallel_delivery_and_dashboard_reads(monitoring):
    c, credential, _ = monitoring
    payload = event()
    with ThreadPoolExecutor(max_workers=6) as pool:
        jobs = [pool.submit(ingest, c, credential, [payload]) for _ in range(8)]
        reads = [pool.submit(c.get, "/api/events") for _ in range(8)]
    assert all(job.result().status_code == 200 for job in jobs + reads)
    assert len(c.get("/api/events").json()["events"]) == 1


def test_failed_commit_never_acknowledged_or_partially_retained(monitoring, monkeypatch):
    from sqlalchemy.exc import OperationalError
    from sqlalchemy.orm import Session

    c, credential, _ = monitoring
    with monkeypatch.context() as patch:

        def full(_db):
            raise OperationalError("COMMIT", {}, Exception("SIMULATED disk full"))

        patch.setattr(Session, "commit", full)
        assert ingest(c, credential, [event()]).status_code == 503
    assert c.get("/api/events").json()["events"] == []
    assert c.get("/api/collection").json()["connection"] == "never_connected"
    assert ingest(c, credential, [event()]).json()["inserted"] == 1


def test_bad_nested_evidence_rejected_and_body_size_bounded(monitoring):
    c, credential, _ = monitoring
    malformed = event(
        evidence={
            "fields": ["not a field mapping"],
            "event_id": 4625,
            "provider": "Microsoft-Windows-Security-Auditing",
        },
        source="Security",
    )
    assert ingest(c, credential, [malformed]).status_code == 422
    oversized = event(evidence={"raw": "x" * 2_100_000})
    assert ingest(c, credential, [oversized]).status_code == 413
    assert c.get("/api/events").json()["events"] == []
