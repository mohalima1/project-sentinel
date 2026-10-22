"""Real launcher, HTTP and Chromium using only an isolated synthetic database."""

import os
import tempfile
import threading
from pathlib import Path
from queue import Queue
from unittest.mock import patch

import uvicorn
from alembic import command
from alembic.config import Config
from playwright.sync_api import expect, sync_playwright
from sentinel.config import ROOT
from sentinel.launch import main


def run():
    urls = Queue()
    servers = []
    real_server = uvicorn.Server

    def capture_server(config):
        server = real_server(config)
        servers.append(server)
        return server

    with tempfile.TemporaryDirectory(prefix="sentinel-local-fixture-") as directory:
        with patch.dict(
            os.environ,
            {
                "SENTINEL_DATABASE_PATH": str(Path(directory) / "test.db"),
                "SENTINEL_COLLECTOR_DISABLED": "1",
            },
        ):
            command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
            with (
                patch("sentinel.launch.webbrowser.open", lambda url: urls.put(url) or True),
                patch("sentinel.launch.uvicorn.Server", capture_server),
            ):
                worker = threading.Thread(target=main)
                worker.start()
                try:
                    url = urls.get(timeout=15)
                    origin = url.split("/#")[0]
                    with sync_playwright() as p:
                        browser = p.chromium.launch()
                        page = browser.new_page(viewport={"width": 1440, "height": 1000})
                        errors = []
                        page.on("pageerror", lambda error: errors.append(str(error)))
                        page.goto(url)
                        expect(
                            page.get_by_role("heading", name="Backend & storage")
                        ).to_be_visible()
                        assert "#" not in page.url
                        assert page.request.get(origin + "/api/status").status == 200
                        page.reload()
                        expect(
                            page.get_by_role("heading", name="Backend & storage")
                        ).to_be_visible()
                        page.get_by_role("button", name="Sign out", exact=True).click()
                        expect(
                            page.get_by_role("heading", name="Open Sentinel locally")
                        ).to_be_visible()
                        assert page.request.get(origin + "/api/status").status == 401
                        assert not page.get_by_label("Password", exact=True).is_visible()
                        (ROOT / "artifacts").mkdir(exist_ok=True)
                        page.screenshot(path=str(ROOT / "artifacts" / "local-entry-desktop.png"))
                        page.set_viewport_size({"width": 390, "height": 844})
                        page.screenshot(
                            path=str(ROOT / "artifacts" / "local-entry-mobile.png"), full_page=True
                        )
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                        page.goto("about:blank")
                        page.goto(url)
                        expect(page.get_by_role("status")).to_contain_text("already used")
                        assert page.request.get(origin + "/api/status").status == 401
                        assert not errors, errors
                        browser.close()
                finally:
                    for server in servers:
                        server.should_exit = True
                    worker.join(timeout=15)
                    assert not worker.is_alive()
    print("PASS: actual local launcher, automatic access, fragment removal, reload, logout,")
    print("replay rejection, desktop/mobile entry, no JS errors; synthetic database removed.")


if __name__ == "__main__":
    run()
