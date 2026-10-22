"""Synthetic local-access and concurrency fixtures; no real host data."""

import hashlib
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from fastapi.testclient import TestClient
from sentinel.accounts import authenticate, create_user
from sentinel.app import create_app
from sentinel.models import User
from sqlalchemy import select
from sqlalchemy.orm import Session

PASSWORD = "synthetic concurrency password"


def test_concurrent_http_login_and_throttling(settings, engine):
    with Session(engine) as db:
        for index in range(4):
            create_user(db, f"fixture-{index}", PASSWORD)
    app = create_app(settings)

    def run_batch(password, same_user=False, count=4):
        barrier = Barrier(count)

        def login(index):
            with TestClient(app, base_url="http://localhost") as client:
                csrf = client.get("/api/auth/csrf").json()["csrf_token"]
                barrier.wait(timeout=10)
                return client.post(
                    "/api/auth/login",
                    json={"username": f"fixture-{0 if same_user else index}", "password": password},
                    headers={"X-CSRF-Token": csrf},
                ).status_code

        with ThreadPoolExecutor(max_workers=count) as workers:
            return list(workers.map(login, range(count)))

    assert run_batch(PASSWORD) == [200] * 4
    failures = run_batch("wrong", same_user=True, count=8)
    assert set(failures) <= {401, 429}
    assert 429 in failures


def test_legacy_password_upgraded_without_lockout(engine):
    salt = bytes.fromhex("01" * 16)
    digest = hashlib.scrypt(PASSWORD.encode(), salt=salt, n=16384, r=8, p=1)
    legacy = f"scrypt${salt.hex()}${digest.hex()}"
    with Session(engine) as db:
        create_user(db, "legacy", PASSWORD)
        user = db.scalar(select(User).where(User.username == "legacy"))
        user.password_hash = legacy
        db.commit()
        assert authenticate(db, "legacy", PASSWORD)
        db.refresh(user)
        assert user.password_hash != legacy
        assert authenticate(db, "legacy", PASSWORD)


def test_local_link_is_one_use_and_logout_stays_protected(settings):
    from sentinel.local_access import LocalAccess

    access = LocalAccess()
    app = create_app(settings, local_access=access)
    with TestClient(app, base_url="http://localhost") as client:
        assert client.get("/api/status").status_code == 401
        assert client.post("/api/auth/local", json={"token": "forged"}).status_code == 401
        response = client.post("/api/auth/local", json={"token": access.token})
        assert response.status_code == 200
        assert client.get("/api/status").status_code == 200
        assert client.post("/api/auth/local", json={"token": access.token}).status_code == 401
        assert client.post("/api/auth/logout").status_code == 403
        assert (
            client.post(
                "/api/auth/logout", headers={"X-CSRF-Token": response.json()["csrf_token"]}
            ).status_code
            == 204
        )
        assert client.get("/api/status").status_code == 401


def test_simultaneous_legacy_upgrade_accepts_both_valid_logins(engine, monkeypatch):
    import sentinel.accounts as accounts

    salt = bytes.fromhex("02" * 16)
    digest = hashlib.scrypt(PASSWORD.encode(), salt=salt, n=16384, r=8, p=1)
    legacy = f"scrypt${salt.hex()}${digest.hex()}"
    with Session(engine) as db:
        create_user(db, "legacy-race", PASSWORD)
        user = db.scalar(select(User).where(User.username == "legacy-race"))
        user.password_hash = legacy
        db.commit()
    barrier = Barrier(2)
    verify = accounts.verify_password

    def synchronized_verify(password, encoded):
        if encoded == legacy:
            barrier.wait(timeout=10)
        return verify(password, encoded)

    # Synchronize the actual KDF boundary so both requests read the old hash.
    monkeypatch.setattr(accounts, "verify_password", synchronized_verify)

    def login(_):
        with Session(engine) as db:
            return bool(authenticate(db, "legacy-race", PASSWORD))

    with ThreadPoolExecutor(max_workers=2) as workers:
        assert list(workers.map(login, range(2))) == [True, True]


def test_local_link_expiry_and_foreign_origin(settings):
    from sentinel.local_access import LocalAccess

    access = LocalAccess()
    with TestClient(create_app(settings, local_access=access), base_url="http://localhost") as c:
        assert (
            c.post(
                "/api/auth/local",
                json={"token": access.token},
                headers={"Origin": "https://evil.example"},
            ).status_code
            == 403
        )
        access.expires_at = 0
        assert c.post("/api/auth/local", json={"token": access.token}).status_code == 401
    with TestClient(create_app(settings), base_url="http://localhost") as c:
        assert c.post("/api/auth/local", json={"token": access.token}).status_code == 401
