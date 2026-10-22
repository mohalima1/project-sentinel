"""Opt-in REAL Windows collection + HTTP/browser acceptance in private isolated data.

No account database is reused. --inventory-change temporarily creates an HKCU
Uninstall metadata marker (not an installed program), then removes it in finally.
No services/tasks/accounts, audit settings or logs are modified.
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime

import uvicorn
from alembic import command
from alembic.config import Config
from playwright.sync_api import expect, sync_playwright
from sentinel.app import create_app
from sentinel.collector.__main__ import sender
from sentinel.collector.runtime import collect_source, deliver
from sentinel.collector.spool import Spool
from sentinel.collector.windows import SOURCES, read_source
from sentinel.config import ROOT, Settings
from sentinel.local_access import LocalAccess
from sentinel.monitoring.credentials import protect_directory, provision


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory-change", action="store_true")
    args = parser.parse_args()
    if os.name != "nt":
        raise SystemExit("Live Windows check requires Windows")
    directory = ROOT / "artifacts" / ("live-" + datetime.now(UTC).strftime("%Y%m%d-%H%M%S"))
    protect_directory(directory)
    path = directory / "sentinel.db"
    os.environ["SENTINEL_DATABASE_PATH"] = str(path)
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    credential = provision(directory / "ingestion.json")
    access = LocalAccess()
    health = {"sources": {}, "failures": 0, "dropped_data": 0}
    checks = {}
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        server = uvicorn.Server(
            uvicorn.Config(
                create_app(Settings(), local_access=access), access_log=False, log_level="warning"
            )
        )
        worker = threading.Thread(target=lambda: server.run(sockets=[listener]))
        worker.start()
        try:
            for _ in range(150):
                if server.started:
                    break
                time.sleep(0.1)
            assert server.started
            send = sender(origin, credential)
            with Spool(directory / "queue.db", credential["host_id"]) as spool:
                for source in SOURCES:
                    collect_source(spool, source, read_source, health["sources"])
                first = spool.pending()
                real = [e for e in first if e["category"] == "windows_event"]
                assert real, "No real Windows log events available"
                first_payload = {
                    "host_id": credential["host_id"],
                    "events": first,
                    "health": health,
                }
                assert send(first_payload)["inserted"] > 0
                assert send(first_payload)["inserted"] == 0
                spool.ack([e["identity"] for e in first])
                while spool.pending():
                    deliver(spool, send, health)
                baseline = spool.state("snapshot:software")
            checks["real_log_http_ingestion_and_replay"] = True
            print(
                "PASS: real Windows logs retained through HTTP; replay inserted zero duplicates.",
                flush=True,
            )
            # Reopen the durable collector state; repeat unchanged inventory.
            with Spool(directory / "queue.db", credential["host_id"]) as spool:
                assert spool.state("snapshot:software") == baseline
                software = read_source("software")
                assert software["status"] == "available"
                spool.snapshot("software", software["items"])
                marker = "SentinelAcceptance-" + uuid.uuid4().hex
                if args.inventory_change:
                    import winreg

                    relative = (
                        r"Software\Microsoft\Windows\CurrentVersion\Uninstall" + "\\" + marker
                    )
                    try:
                        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, relative) as key:
                            winreg.SetValueEx(
                                key,
                                "DisplayName",
                                0,
                                winreg.REG_SZ,
                                "Sentinel reversible acceptance marker (not installed software)",
                            )
                            winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, "1.0-test")
                        collect_source(spool, "software", read_source, health["sources"])
                        changes = [
                            e
                            for e in spool.pending()
                            if e["category"] == "inventory_change"
                            and marker in e["evidence"]["item"]
                        ]
                        assert len(changes) == 1
                        assert changes[0]["evidence"]["before"] is None
                        assert changes[0]["evidence"]["after"]["Version"] == "1.0-test"
                        while spool.pending():
                            deliver(spool, send, health)
                    finally:
                        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, relative)
                    collect_source(spool, "software", read_source, health["sources"])
                    removals = [
                        e for e in spool.pending() if marker in e["evidence"].get("item", "")
                    ]
                    assert len(removals) == 1 and removals[0]["evidence"]["after"] is None
                    while spool.pending():
                        deliver(spool, send, health)
                    checks["reversible_real_registry_inventory_change"] = True
            checks["collector_restart_preserved_progress"] = True
            print(
                "PASS: collector state restart and optional reversible inventory evidence.",
                flush=True,
            )
            # Execute the collector's actual process boundary after queue/backend ingestion.
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "sentinel.collector",
                    "--once",
                    "--data-dir",
                    str(directory),
                    "--url",
                    origin,
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )
            assert completed.returncode == 0, completed.stderr
            checks["separate_collector_process"] = True
            print("PASS: separate collector process delivered to the real backend.", flush=True)
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page(viewport={"width": 1440, "height": 1000})
                errors = []
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(origin + "/#local=" + access.token)
                expect(page.get_by_role("heading", name="Backend & storage")).to_be_visible()
                result = page.request.get(origin + "/api/events?source=System").json()["events"]
                assert result
                record = page.request.get(origin + f"/api/events/{result[0]['id']}").json()
                assert record["evidence"]["xml"].startswith("<Event")
                page.get_by_role("button", name="Events", exact=True).click()
                page.get_by_label("Source", exact=True).select_option("System")
                page.get_by_role("button", name="Apply filters").click()
                expect(page.locator(".timeline > li").first).to_be_visible()
                page.locator(".evidence summary").first.click()
                expect(page.locator("pre").first).to_contain_text("EventID")
                page.screenshot(path=str(directory / "events-desktop.png"), full_page=True)
                page.get_by_role("button", name="Collection health", exact=True).click()
                expect(
                    page.get_by_role("heading", name="Source availability and permissions")
                ).to_be_visible()
                expect(page.get_by_role("heading", name="Security", exact=True)).to_be_visible()
                page.screenshot(path=str(directory / "health-desktop.png"), full_page=True)
                page.set_viewport_size({"width": 390, "height": 844})
                tabs = (
                    "Overview",
                    "Changes",
                    "Events",
                    "Alerts",
                    "Collection health",
                    "Settings & audit",
                )
                for tab in tabs:
                    page.get_by_role("button", name=tab, exact=True).click()
                    page.wait_for_timeout(250)
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), tab
                page.screenshot(path=str(directory / "settings-mobile.png"), full_page=True)
                assert not errors, errors
                browser.close()
                checks["real_windows_event_in_authenticated_browser_search"] = True
                checks["all_sections_mobile_no_overflow_or_js_errors"] = True
        finally:
            server.should_exit = True
            worker.join(timeout=15)
            assert not worker.is_alive()
    sources_summary = {name: value["status"] for name, value in health["sources"].items()}
    report = {
        "checks": checks,
        "sources": sources_summary,
        "note": (
            "REAL host collection. Reversible test marker is metadata only, "
            "not an installed program. No disruptive checks."
        ),
    }
    (directory / "result.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"Private evidence retained in {directory.relative_to(ROOT)} (ignored).")


if __name__ == "__main__":
    main()
