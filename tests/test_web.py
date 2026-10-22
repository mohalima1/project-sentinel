import time

import pytest
from fastapi.testclient import TestClient
from sentinel.models import LoginSession
from sqlalchemy import select
from sqlalchemy.orm import Session

PASSWORD = "synthetic fixture password"


@pytest.fixture
def client(settings, engine):
    from sentinel.accounts import create_user
    from sentinel.app import create_app

    with Session(engine) as db:
        create_user(db, "admin", PASSWORD)
    with TestClient(create_app(settings), base_url="http://localhost") as browser:
        yield browser


def sign_in(client, password=PASSWORD, username="admin"):
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
        headers={"X-CSRF-Token": csrf, "Origin": "http://localhost"},
    )


def test_dashboard_api_requires_authentication(client):
    for path in ["/api/auth/session", "/api/status", "/api/audit"]:
        assert client.get(path).status_code == 401
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/docs").status_code == 404


def test_login_status_and_logout_flow(client):
    response = sign_in(client)
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    session = response.json()
    assert session["username"] == "admin"
    assert session["expires_at"] > time.time()
    status = client.get("/api/status")
    assert status.headers["cache-control"] == "no-store"
    assert "default-src 'self'" in status.headers["content-security-policy"]
    data = status.json()
    assert data["database"]["revision"] == "0002"
    assert data["database"]["users"] == 1
    assert data["database"]["active_sessions"] == 1
    assert data["telemetry"]["status"] == "unavailable"
    assert data["host_controls_enabled"] is False
    assert client.get("/api/audit").json()["events"][0]["action"] == "signed_in"
    token = client.cookies.get("sentinel_session")
    assert (
        client.post("/api/auth/logout", headers={"X-CSRF-Token": session["csrf_token"]}).status_code
        == 204
    )
    client.cookies.set("sentinel_session", token)
    assert client.get("/api/status").status_code == 401


def test_wrong_password_and_unknown_account_have_same_error(client):
    first = sign_in(client, "wrong password")
    second = sign_in(client, "wrong password", "unknown")
    assert first.status_code == second.status_code == 401
    assert first.json() == second.json() == {"detail": "Invalid username or password."}
    assert client.get("/api/status").status_code == 401


def test_login_throttle_is_enforced_by_http(client):
    for _ in range(5):
        assert sign_in(client, "wrong").status_code == 401
    response = sign_in(client)
    assert response.status_code == 429
    assert response.headers["retry-after"] == "300"


@pytest.mark.parametrize("token", [None, "forged", "\u2603"])
def test_login_rejects_missing_and_forged_csrf(client, token):
    client.get("/api/auth/csrf")
    # HTTP headers are ASCII; encode a Unicode token as UTF-8 to exercise bad input.
    headers = {"X-CSRF-Token": token.encode("utf-8")} if token else {}
    assert (
        client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}, headers=headers
        ).status_code
        == 403
    )


def test_logout_requires_session_csrf(client):
    sign_in(client)
    assert client.post("/api/auth/logout").status_code == 403
    assert client.get("/api/status").status_code == 200
    assert client.get("/api/auth/logout").status_code == 405


def test_foreign_origin_and_dns_rebinding_are_rejected(client):
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    assert (
        client.post(
            "/api/auth/login",
            json={"username": "admin", "password": PASSWORD},
            headers={"Origin": "http://evil.example", "X-CSRF-Token": csrf},
        ).status_code
        == 403
    )
    assert client.get("/healthz", headers={"Host": "evil.example"}).status_code == 400


def test_input_validation_and_injection_remain_unauthenticated(client):
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    assert (
        client.post(
            "/api/auth/login",
            json={"username": "x" * 65, "password": PASSWORD},
            headers={"X-CSRF-Token": csrf},
        ).status_code
        == 422
    )
    assert sign_in(client, PASSWORD, "' OR 1=1 --").status_code == 401


def test_expired_session_is_rejected(client, engine):
    sign_in(client)
    with Session(engine) as db:
        login = db.scalar(select(LoginSession))
        login.expires_at = int(time.time()) - 1
        db.commit()
    assert client.get("/api/status").status_code == 401


def test_session_survives_application_restart(client, settings):
    from sentinel.app import create_app

    sign_in(client)
    with TestClient(create_app(settings), base_url="http://localhost") as restarted:
        restarted.cookies.set("sentinel_session", client.cookies.get("sentinel_session"))
        assert restarted.get("/api/auth/session").json()["username"] == "admin"
        assert restarted.get("/api/status").status_code == 200


def test_startup_refuses_unmigrated_database(tmp_path):
    from sentinel.app import create_app
    from sentinel.config import Settings

    with pytest.raises(RuntimeError, match="uv run alembic upgrade head"):
        with TestClient(create_app(Settings(database_path=tmp_path / "empty.db"))):
            pass
