"""Readiness diagnostic with synthetic accounts in an isolated temporary database.

Run: uv run --locked python tests/concurrent_login_check.py
Exit 1 means at least one valid concurrent login failed. This is intentionally
separate from the milestone-1 pytest suite so its uncovered gap stays explicit.
"""

import os
import secrets
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

from alembic import command
from alembic.config import Config
from sentinel.accounts import authenticate, create_user
from sentinel.config import ROOT
from sentinel.db import make_engine
from sqlalchemy.orm import Session


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sentinel-concurrency-fixture-") as directory:
        path = Path(directory) / "fixture.db"
        os.environ["SENTINEL_DATABASE_PATH"] = str(path)
        command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
        engine = make_engine(path)
        password = secrets.token_urlsafe(24)
        try:
            for index in range(4):
                with Session(engine) as db:
                    create_user(db, f"fixture-{index}", password)
            barrier = Barrier(4)

            def login(index):
                barrier.wait(timeout=5)
                try:
                    with Session(engine) as db:
                        token = authenticate(db, f"fixture-{index}", password)
                        return "authenticated" if token else "denied"
                except Exception as exc:
                    # Avoid printing SQL parameters, passwords, or raw tokens.
                    return type(exc).__name__ + ": " + str(exc).splitlines()[0]

            with ThreadPoolExecutor(max_workers=4) as workers:
                results = list(workers.map(login, range(4)))
            for index, result in enumerate(results):
                print(f"Synthetic login {index + 1}: {result}")
            passed = results.count("authenticated")
            print(f"Concurrent valid logins: {passed}/4 succeeded.")
        finally:
            engine.dispose()
    return 0 if passed == 4 else 1


if __name__ == "__main__":
    raise SystemExit(main())
