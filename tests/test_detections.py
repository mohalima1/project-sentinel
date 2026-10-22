"""Positive and negative SYNTHETIC Windows rule fixtures, never live proof."""

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from test_monitoring import event, ingest, monitoring  # noqa: F401, F811

SECURITY = "Microsoft-Windows-Security-Auditing"
DEFENDER = "Microsoft-Windows-Windows Defender/Operational"


def windows(n, event_id, *, source="Security", provider=SECURITY, fields=None, **changes):
    return event(
        identity=hashlib.sha256(f"synthetic-{n}".encode()).hexdigest(),
        source=source,
        evidence={
            "synthetic_fixture": True,
            "xml": "<Event>SYNTHETIC</Event>",
            "provider": provider,
            "event_id": event_id,
            "fields": fields or {},
        },
        **changes,
    )


@pytest.mark.parametrize(
    "payload,rule",
    [
        (
            windows(
                1, 4732, fields={"TargetSid": "S-1-5-32-544", "MemberSid": "synthetic-account"}
            ),
            "administrators",
        ),
        (windows(2, 4733, fields={"TargetSid": "S-1-5-32-544"}), "administrators"),
        (windows(3, 4697, fields={"ServiceName": "fixture-service"}), "service_install"),
        (
            windows(
                4,
                7045,
                source="System",
                provider="Service Control Manager",
                fields={"ServiceName": "fixture"},
            ),
            "service_install",
        ),
        (windows(5, 4698, fields={"TaskName": "\\SyntheticTask"}), "scheduled_task"),
        (windows(6, 4702, fields={"TaskName": "\\SyntheticTask"}), "scheduled_task"),
        (windows(7, 1102, provider="Microsoft-Windows-Eventlog"), "security_log_cleared"),
        (
            windows(8, 1116, source=DEFENDER, provider="Microsoft-Windows-Windows Defender"),
            "defender_threat",
        ),
    ],
)
def test_positive_windows_rules_with_explanation_and_evidence(monitoring, payload, rule):
    c, credential, _ = monitoring
    assert ingest(c, credential, [payload]).status_code == 200
    alerts = c.get("/api/alerts").json()["alerts"]
    assert len(alerts) == 1 and alerts[0]["rule"] == rule
    alert = c.get(f"/api/alerts/{alerts[0]['id']}").json()
    assert alert["state"] == "new" and alert["explanation"]["why"]
    assert alert["explanation"]["legitimate"] and alert["explanation"]["steps"]
    assert (
        alert["explanation"]["references"]
        and alert["evidence"][0]["evidence"] == payload["evidence"]
    )
    assert "compromise" in alert["explanation"]["interpretation"]
    assert ingest(c, credential, [payload]).json()["inserted"] == 0
    assert len(c.get("/api/alerts").json()["alerts"]) == 1


def test_negative_sources_providers_groups_and_baselines(monitoring):
    c, credential, _ = monitoring
    fixtures = [
        windows(1, 4732, fields={"TargetSid": "S-1-5-32-545"}),
        windows(2, 4698, source="Application"),
        windows(3, 1116, source=DEFENDER, provider="Unrelated"),
        windows(4, 1102, provider=SECURITY),
        windows(5, 7045, source="System", provider="Unrelated"),
        event(source="administrators", category="inventory_baseline"),
        event("b", source="tasks", category="inventory_baseline"),
        windows(6, 4624),
    ]
    assert ingest(c, credential, fixtures).status_code == 200
    assert c.get("/api/alerts").json()["alerts"] == []


def test_failed_windows_signins_threshold_window_account_and_reordering(monitoring):
    c, credential, _ = monitoring
    now = datetime.now(UTC)
    fields = {
        "TargetUserName": "synthetic-user",
        "TargetDomainName": "fixture",
        "IpAddress": "192.0.2.1",
    }
    fixtures = [
        windows(i, 4625, fields=fields, observed_at=(now - timedelta(seconds=i)).isoformat())
        for i in range(1, 6)
    ]
    assert ingest(c, credential, fixtures[:4]).status_code == 200
    assert c.get("/api/alerts").json()["alerts"] == []
    assert (
        ingest(
            c, credential, [windows(77, 4625, fields={**fields, "TargetUserName": "other"})]
        ).status_code
        == 200
    )
    assert c.get("/api/alerts").json()["alerts"] == []
    assert ingest(c, credential, fixtures[4:]).status_code == 200
    alerts = c.get("/api/alerts").json()["alerts"]
    assert len(alerts) == 1 and alerts[0]["rule"] == "failed_windows_signins"
    assert len(c.get(f"/api/alerts/{alerts[0]['id']}").json()["evidence"]) == 5
    assert "Windows" in alerts[0]["title"]
    later = windows(90, 4625, fields=fields, observed_at=(now - timedelta(hours=1)).isoformat())
    assert ingest(c, credential, [later]).status_code == 200
    assert len(c.get("/api/alerts").json()["alerts"]) == 1


def test_inventory_changes_and_investigation_and_suppression(monitoring):
    c, credential, session = monitoring
    payload = event(
        source="services",
        category="inventory_change",
        evidence={
            "change": "added",
            "item": "fixture",
            "before": None,
            "after": {"PathName": "fixture.exe"},
        },
    )
    assert ingest(c, credential, [payload]).status_code == 200
    alert = c.get("/api/alerts").json()["alerts"][0]
    endpoint = f"/api/alerts/{alert['id']}"
    assert c.patch(endpoint, json={"state": "resolved"}).status_code == 403
    headers = {"X-CSRF-Token": session["csrf_token"]}
    for state in ("investigating", "resolved", "false_positive", "new"):
        assert c.patch(endpoint, json={"state": state}, headers=headers).status_code == 200
        assert c.get("/api/alerts", params={"state": state}).json()["alerts"][0]["state"] == state
    assert c.patch(endpoint, json={"state": "compromised"}, headers=headers).status_code == 422
    assert (
        c.put(
            "/api/suppressions/service_install",
            json={"seconds": 3600, "reason": "Synthetic maintenance"},
            headers=headers,
        ).status_code
        == 200
    )
    assert (
        ingest(c, credential, [windows(4, 4697, fields={"ServiceName": "other"})]).status_code
        == 200
    )
    assert len(c.get("/api/alerts").json()["alerts"]) == 1
    assert len(c.get("/api/events").json()["events"]) == 2  # Suppression never deletes facts.
    assert c.delete("/api/suppressions/service_install", headers=headers).status_code == 204
    assert (
        ingest(c, credential, [windows(5, 4697, fields={"ServiceName": "third"})]).status_code
        == 200
    )
    assert len(c.get("/api/alerts").json()["alerts"]) == 2


def test_alerts_require_browser_auth(monitoring):
    c, _, _ = monitoring
    c.cookies.clear()
    assert c.get("/api/alerts").status_code == 401
    assert c.get("/api/suppressions").status_code == 401
