import json
import os
import subprocess
from pathlib import Path

LOGS = (
    "System",
    "Security",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Sysmon/Operational",
)
INVENTORIES = ("services", "tasks", "startup", "administrators", "software")
SOURCES = (*LOGS, *INVENTORIES, "audit_policy")


def read_source(source, cursor=None):
    if source not in SOURCES:
        raise ValueError("Unknown read-only source")
    if os.name != "nt":
        return {"status": "unavailable", "error": "Windows collection requires Windows x64."}
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    command = [
        str(powershell),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(Path(__file__).with_name("windows.ps1")),
        "-Source",
        source,
    ]
    if cursor is not None:
        command += ["-HasCursor", "-After", str(cursor["record"])]
        if cursor["anchor_hash"]:
            command += ["-AnchorHash", cursor["anchor_hash"]]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode != 0:
            return {
                "status": "error",
                "error": result.stderr.strip()[:1000] or "Windows reader failed",
            }
        return json.loads(result.stdout.lstrip("\ufeff"))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "error": str(exc)[:1000]}
