import os
import sqlite3
import subprocess
import sys


def migrate(path, target="head", direction="upgrade"):
    return subprocess.run(
        [sys.executable, "-m", "alembic", direction, target],
        env={**os.environ, "SENTINEL_DATABASE_PATH": str(path)},
        capture_output=True,
        text=True,
    )


def test_migration_upgrade_preserves_data_and_is_repeatable(tmp_path):
    path = tmp_path / "nested" / "sentinel.db"
    result = migrate(path)
    assert result.returncode == 0, result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT version_num FROM alembic_version").fetchone() == ("0002",)
        db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            ("admin", "hash", 1000),
        )
    assert migrate(path).returncode == 0
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT username FROM users").fetchall() == [("admin",)]


def test_migration_downgrade_and_reupgrade(tmp_path):
    path = tmp_path / "sentinel.db"
    assert migrate(path).returncode == 0
    assert migrate(path, "base", "downgrade").returncode == 0
    with sqlite3.connect(path) as db:
        assert not db.execute("SELECT name FROM sqlite_master WHERE name='users'").fetchall()
    assert migrate(path).returncode == 0


def test_engine_enforces_foreign_keys(tmp_path):
    from sentinel.db import make_engine
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    path = tmp_path / "sentinel.db"
    assert migrate(path).returncode == 0
    engine = make_engine(path)
    try:
        with engine.begin() as db:
            try:
                db.execute(
                    text(
                        "INSERT INTO sessions "
                        "(token_hash, user_id, csrf_token, created_at, expires_at) "
                        "VALUES ('hash', 999, 'csrf', 1000, 2000)"
                    )
                )
            except IntegrityError:
                pass
            else:
                raise AssertionError("Orphan session was accepted")
    finally:
        engine.dispose()
