"""Start a loopback-only dashboard and open a one-use browser access link."""

import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser

import uvicorn

from sentinel.app import create_app
from sentinel.config import ROOT, Settings
from sentinel.db import make_engine, require_schema
from sentinel.local_access import LocalAccess
from sentinel.monitoring.credentials import credential_path, provision


def main() -> int:
    if not (ROOT / "frontend" / "dist" / "index.html").is_file():
        print("Run scripts\\setup.cmd first to build Sentinel.")
        return 1
    settings = Settings()
    engine = make_engine(settings.database_path)
    try:
        require_schema(engine)
    except RuntimeError:
        from alembic import command
        from alembic.config import Config

        print("Preparing Sentinel's database migrations; existing accounts are preserved.")
        command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    finally:
        engine.dispose()
    access = LocalAccess()
    collector = None
    with socket.socket() as listener:
        # Reserve an available port before opening the browser. No occupied-port race.
        listener.bind(("127.0.0.1", int(os.environ.get("SENTINEL_LISTEN_PORT", "0"))))
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        server = uvicorn.Server(
            uvicorn.Config(
                create_app(settings, local_access=access), access_log=False, log_level="warning"
            )
        )

        def open_browser():
            for _ in range(300):
                if server.started:
                    # Fragment never travels in HTTP URLs, access logs or referrers.
                    if not webbrowser.open(origin + "/#local=" + access.token):
                        print("Browser did not open. Set a default browser and restart Sentinel.")
                    return
                if server.should_exit:
                    return
                time.sleep(0.1)
            print("Sentinel did not start within 30 seconds. Check the terminal errors.")
            server.should_exit = True

        print("Opening Sentinel locally. Keep this window open; press Ctrl+C to stop.")
        threading.Thread(target=open_browser, daemon=True).start()

        def start_collector():
            nonlocal collector
            if os.environ.get("SENTINEL_COLLECTOR_DISABLED") == "1":
                return  # Explicit synthetic browser tests / separate service collector only.
            provision(credential_path(settings.database_path))
            collector = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "sentinel.collector",
                    "--data-dir",
                    str(settings.database_path.parent),
                    "--url",
                    origin,
                ],
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )

        try:
            start_collector()
            server.run(sockets=[listener])
        finally:
            if collector and collector.poll() is None:
                collector.terminate()
                collector.wait(timeout=10)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
