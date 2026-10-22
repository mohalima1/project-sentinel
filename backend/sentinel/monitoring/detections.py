"""Small evidence-based rule set. Facts do not establish confirmed compromise."""

import hashlib
import time
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert

from sentinel.monitoring.models import Alert, AlertEvidence, HostEvent, Suppression
from sentinel.monitoring.schemas import utc

AUDIT = "Microsoft-Windows-Security-Auditing"
DOCS = "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/"
RULES = {
    "failed_windows_signins": {
        "title": "Repeated failed Windows sign-ins",
        "severity": "medium",
        "why": "A burst of failed Windows authentication can indicate password guessing or a broken stored credential.",
        "legitimate": [
            "Mistyped passwords",
            "An expired password saved in a service, mapped drive or scheduled task",
        ],
        "steps": [
            "Compare TargetUserName, IpAddress, LogonType, Status and SubStatus in each event.",
            "Check whether the account owner or the named service recognizes these attempts.",
            "Review nearby successful Windows sign-ins (4624) in Event Viewer; investigate unfamiliar origins.",
        ],
        "prerequisites": "Security log read permission and Audit Logon failure auditing. These are Windows sign-ins, separate from Sentinel dashboard activity.",
        "references": [DOCS + "event-4625"],
    },
    "administrators": {
        "title": "Local administrator membership changed",
        "severity": "high",
        "why": "Local Administrators membership grants broad control of this computer. An unexpected change deserves review.",
        "legitimate": [
            "Approved IT provisioning",
            "Device enrollment or authorized account maintenance",
        ],
        "steps": [
            "Compare the member SID/name and before/after membership evidence.",
            "For Security events, identify SubjectUserName and verify an approved change request.",
            "Inspect Local Users and Groups and account ownership before deciding whether access should change.",
        ],
        "prerequisites": "Snapshot access to the built-in group SID S-1-5-32-544; Security 4732/4733 additionally require Audit Security Group Management success auditing.",
        "references": [DOCS + "event-4732", DOCS + "event-4733"],
    },
    "service_install": {
        "title": "New Windows service observed",
        "severity": "medium",
        "why": "Services can run automatically with powerful accounts. A new service may introduce persistent code execution.",
        "legitimate": [
            "Software or driver installation",
            "An approved updater or management agent",
        ],
        "steps": [
            "Inspect ServiceName, executable path, service account and start mode in the original evidence.",
            "Check the executable's signature and publisher in file properties without launching it.",
            "Compare the installation time with software changes and your approved installations.",
        ],
        "prerequisites": "System 7045 from Service Control Manager, service snapshot access, or Security 4697 with Audit Security System Extension success auditing.",
        "references": [DOCS + "event-4697"],
    },
    "scheduled_task": {
        "title": "Scheduled task created or modified",
        "severity": "medium",
        "why": "A task can run code at logon or on a schedule. Unexpected actions or principals may create persistent access.",
        "legitimate": [
            "Windows or application updates",
            "A task intentionally configured by the user or administrator",
        ],
        "steps": [
            "Inspect TaskName, task XML actions, arguments, triggers and run-as principal.",
            "Compare before/after XML for snapshot changes; exact change time lies between the snapshots.",
            "Inspect the referenced executable's signature and ask whether its owner expects this schedule.",
        ],
        "prerequisites": "Task inventory read access, or Security 4698/4702 with Audit Other Object Access Events success auditing. TaskScheduler Operational availability is reported separately.",
        "references": [
            DOCS + "event-4698",
            DOCS + "event-4702",
            DOCS + "audit-other-object-access-events",
        ],
    },
    "security_log_cleared": {
        "title": "Windows Security log was cleared",
        "severity": "high",
        "why": "Clearing the audit log removes historical evidence and can hinder investigation.",
        "legitimate": [
            "Approved troubleshooting or image preparation",
            "An authorized log maintenance procedure",
        ],
        "steps": [
            "Identify SubjectUserName, SubjectUserSid and SubjectLogonId in the original XML.",
            "Confirm an approved reason and compare the time with administrative activity.",
            "Review retained Sentinel events and external backups; inspect collection gaps for missing history.",
        ],
        "prerequisites": "Read access to Security; event 1102 from Microsoft-Windows-Eventlog. Cursor resets alone are collection gaps, not proof that someone cleared the Security log.",
        "references": [DOCS + "event-1102"],
    },
    "defender_threat": {
        "title": "Microsoft Defender reported a threat",
        "severity": "high",
        "why": "Defender reported malware or potentially unwanted software. A detection alone does not establish execution or successful remediation.",
        "legitimate": [
            "A quarantined download that never ran",
            "An antivirus false positive or authorized test artifact",
        ],
        "steps": [
            "Open Windows Security > Virus & threat protection > Protection history and match the threat and path.",
            "Check nearby Defender action events, including 1117, 1118 and 1119, for the outcome.",
            "Review the affected file's origin without opening it and follow Windows Security's current remediation guidance.",
        ],
        "prerequisites": "Microsoft-Windows-Windows Defender/Operational event 1116 from Microsoft-Windows-Windows Defender. Another antivirus or disabled Defender may leave this source unavailable.",
        "references": [
            "https://learn.microsoft.com/en-us/defender-endpoint/"
            "troubleshoot-microsoft-defender-antivirus"
        ],
    },
}


def classify(event):
    evidence = event.evidence
    fields = evidence.get("fields", {})
    if event.category == "inventory_change":
        change = evidence.get("change")
        if event.source == "administrators" and change in {"added", "removed"}:
            return "administrators", evidence.get("item", "unknown")
        if event.source == "services" and change == "added":
            return "service_install", evidence.get("item", "unknown")
        if event.source == "tasks" and change in {"added", "modified"}:
            return "scheduled_task", evidence.get("item", "unknown")
    if event.category != "windows_event":
        return None
    code, provider = evidence.get("event_id"), evidence.get("provider")
    if event.source == "Security" and provider == AUDIT:
        if code == 4625:
            # Separate target domains and source addresses, including unknown address markers.
            return "failed_windows_signins", "|".join(
                str(fields.get(key, "unknown"))
                for key in ("TargetDomainName", "TargetUserName", "IpAddress")
            )
        if code in {4732, 4733} and fields.get("TargetSid") == "S-1-5-32-544":
            return "administrators", fields.get("MemberSid") or fields.get("MemberName", "unknown")
        if code == 4697:
            return "service_install", fields.get("ServiceName", "unknown")
        if code in {4698, 4702}:
            return "scheduled_task", fields.get("TaskName", "unknown")
    if event.source == "System" and provider == "Service Control Manager" and code == 7045:
        return "service_install", fields.get("ServiceName", "unknown")
    if event.source == "Security" and provider == "Microsoft-Windows-Eventlog" and code == 1102:
        return "security_log_cleared", fields.get("SubjectUserSid", "unknown")
    if (
        event.source == "Microsoft-Windows-Windows Defender/Operational"
        and provider == "Microsoft-Windows-Windows Defender"
        and code == 1116
    ):
        return "defender_threat", fields.get(
            "Threat ID", fields.get("Threat Name", "unknown")
        ) + "|" + fields.get("Path", "unknown")
    return None


def detect(db, event, policy):
    match = classify(event)
    if not match:
        return
    rule, entity = match
    suppression = db.get(Suppression, rule)
    if suppression and suppression.until > time.time():
        return
    evidence = [event]
    now = datetime.fromisoformat(event.observed_at.replace("Z", "+00:00"))
    window = policy.failed_logon_window_seconds if rule == "failed_windows_signins" else 600
    if rule == "failed_windows_signins":
        # Evaluate adjacent event-time windows so out-of-order deliveries can cross the threshold.
        neighbors = db.scalars(
            select(HostEvent)
            .where(
                HostEvent.host_id == event.host_id,
                HostEvent.source == "Security",
                HostEvent.observed_at >= utc(now - timedelta(seconds=window)),
                HostEvent.observed_at <= utc(now + timedelta(seconds=window)),
            )
            .order_by(HostEvent.observed_at)
        ).all()
        candidates = [e for e in neighbors if classify(e) == match]
        evidence = []
        for end in candidates:
            end_time = datetime.fromisoformat(end.observed_at.replace("Z", "+00:00"))
            start = utc(end_time - timedelta(seconds=window))
            group = [e for e in candidates if start <= e.observed_at <= end.observed_at]
            if len(group) >= policy.failed_logon_threshold and any(e.id == event.id for e in group):
                evidence = group
                break
        if not evidence:
            return
    first, last = min(e.observed_at for e in evidence), max(e.observed_at for e in evidence)
    alert = db.scalar(
        select(Alert)
        .where(
            Alert.rule == rule,
            Alert.explanation["entity"].as_string() == entity,
            Alert.last_seen >= utc(now - timedelta(seconds=window)),
            Alert.first_seen <= utc(now + timedelta(seconds=window)),
        )
        .order_by(Alert.id.desc())
        .limit(1)
    )
    if alert is None:
        explanation = {
            **RULES[rule],
            "entity": entity,
            "interpretation": "This observation warrants review; it is not proof of compromise.",
            "facts": (
                "Triggering events and original evidence are linked below. "
                "Snapshot changes are bounded by collection times."
            ),
            "threshold": policy.failed_logon_threshold if rule == "failed_windows_signins" else 1,
            "window_seconds": window,
        }
        fingerprint = hashlib.sha256(f"{rule}:{entity}:{event.identity}".encode()).hexdigest()
        alert = Alert(
            fingerprint=fingerprint,
            rule=rule,
            severity=RULES[rule]["severity"],
            title=RULES[rule]["title"],
            first_seen=first,
            last_seen=last,
            state="new",
            explanation=explanation,
        )
        db.add(alert)
        db.flush()
    else:
        alert.first_seen, alert.last_seen = min(alert.first_seen, first), max(alert.last_seen, last)
    for item in evidence:
        db.execute(
            insert(AlertEvidence)
            .values(alert_id=alert.id, event_id=item.id)
            .on_conflict_do_nothing()
        )


def serialize_alert(db, alert):
    from sentinel.monitoring.api import serialize_event

    evidence = db.scalars(
        select(HostEvent)
        .join(AlertEvidence)
        .where(AlertEvidence.alert_id == alert.id)
        .order_by(HostEvent.observed_at)
        .limit(101)
    ).all()
    result = {
        key: getattr(alert, key)
        for key in (
            "id",
            "rule",
            "severity",
            "title",
            "first_seen",
            "last_seen",
            "state",
            "explanation",
        )
    }
    result["evidence"] = [serialize_event(e) for e in evidence[:100]]
    result["more_evidence"] = len(evidence) > 100
    return result
