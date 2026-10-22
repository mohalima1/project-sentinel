"""Real HTTP + Chromium checks using a temporary database and synthetic test account.

Run after `npm.cmd --prefix frontend run build` and `uv run playwright install chromium`.
No real host telemetry or permanent development account is created.
"""

import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from alembic import command
from alembic.config import Config
from playwright.sync_api import expect, sync_playwright
from sentinel.accounts import create_user
from sentinel.config import ROOT
from sentinel.db import make_engine
from sqlalchemy.orm import Session


def serve(port):
    import uvicorn

    server = uvicorn.Server(uvicorn.Config("sentinel.app:app", host="127.0.0.1", port=port))

    def stop_on_input():
        sys.stdin.read(1)
        server.should_exit = True

    threading.Thread(target=stop_on_input, daemon=True).start()
    server.run()


def main():
    if not (ROOT / "frontend" / "dist" / "index.html").exists():
        raise SystemExit("Build frontend first: npm.cmd --prefix frontend run build")
    screenshots = ROOT / "artifacts"
    screenshots.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sentinel-synthetic-") as directory:
        path = Path(directory) / "fixture.db"
        os.environ["SENTINEL_DATABASE_PATH"] = str(path)
        command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
        password = secrets.token_urlsafe(24)
        engine = make_engine(path)
        with Session(engine) as db:
            create_user(db, "fixture-admin", password)
        engine.dispose()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        with (screenshots / "browser-server.log").open("w") as logs:
            server = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--serve", str(port)],
                cwd=ROOT,
                stdout=logs,
                stderr=logs,
                stdin=subprocess.PIPE,
            )
            try:
                for _ in range(100):
                    if server.poll() is not None:
                        raise AssertionError("Uvicorn exited; inspect artifacts/browser-server.log")
                    try:
                        with urlopen(origin + "/healthz", timeout=1) as result:
                            assert result.status == 200
                        break
                    except URLError:
                        time.sleep(0.1)
                else:
                    raise AssertionError("Uvicorn startup timed out")
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch()
                    page = browser.new_page(viewport={"width": 1440, "height": 1050})
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.goto(origin)
                    expect(
                        page.get_by_role("heading", name="Open Sentinel locally")
                    ).to_be_visible()
                    page.get_by_text("Use an existing password account", exact=True).click()
                    page.screenshot(path=str(screenshots / "login-desktop.png"), full_page=True)
                    page.get_by_label("Username", exact=True).fill("fixture-admin")
                    page.get_by_label("Password", exact=True).fill("wrong password")
                    page.get_by_role("button", name="Sign in", exact=True).click()
                    expect(page.get_by_role("alert")).to_have_text("Invalid username or password.")
                    page.get_by_label("Password", exact=True).fill(password)
                    page.get_by_label("Password", exact=True).press("Enter")
                    expect(
                        page.get_by_role("heading", name="No host security assessment yet")
                    ).to_be_visible()
                    expect(page.get_by_text("Telemetry unavailable", exact=True)).to_be_visible()
                    assert page.request.get(origin + "/api/status").json()["database"]["users"] == 1
                    page.reload()
                    expect(page.get_by_role("heading", name="Backend & storage")).to_be_visible()
                    page.screenshot(path=str(screenshots / "dashboard-desktop.png"), full_page=True)
                    page.get_by_role("button", name="View audit log").click()
                    expect(
                        page.get_by_role("heading", name="Settings & audit", exact=True)
                    ).to_be_visible()
                    expect(page.get_by_text("Sign-in failed", exact=True)).to_be_visible()
                    page.get_by_role("button", name="Overview", exact=True).click()
                    page.route("**/api/status", lambda route: route.abort())
                    page.get_by_role("button", name="Refresh", exact=True).click()
                    expect(page.get_by_role("alert")).to_contain_text("Backend unavailable")
                    expect(page.get_by_role("alert")).to_contain_text("previously loaded data")
                    page.unroute("**/api/status")
                    page.get_by_role("button", name="Refresh", exact=True).click()
                    expect(page.get_by_role("alert")).to_have_count(0)
                    page.set_viewport_size({"width": 390, "height": 844})
                    page.screenshot(path=str(screenshots / "dashboard-mobile.png"), full_page=True)
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                    # Another tab/launcher rotates the shared browser session cookie.
                    csrf = page.request.get(origin + "/api/auth/csrf").json()["csrf_token"]
                    rotated = page.request.post(
                        origin + "/api/auth/login",
                        data={"username": "fixture-admin", "password": password},
                        headers={"X-CSRF-Token": csrf},
                    )
                    assert rotated.status == 200
                    page.get_by_role("button", name="Sign out", exact=True).click()
                    expect(
                        page.get_by_role("heading", name="Open Sentinel locally")
                    ).to_be_visible()
                    assert page.request.get(origin + "/api/status").status == 401
                    page.screenshot(path=str(screenshots / "login-mobile.png"), full_page=True)
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                    assert errors == [], errors
                    browser.close()
            finally:
                # Graceful shutdown closes SQLite before Windows removes the fixture.
                if server.poll() is None:
                    server.stdin.write(b"\n")
                    server.stdin.flush()
                server.wait(timeout=15)
                server.stdin.close()
    print("PASS: live HTTP health; desktop/mobile login, wrong password, keyboard submit;")
    print("session reload, status/audit, offline retry, logout; no overflow or JS errors.")
    print("Server shut down gracefully and synthetic fixture database removed.")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--serve":
        serve(int(sys.argv[2]))
    else:
        main()
