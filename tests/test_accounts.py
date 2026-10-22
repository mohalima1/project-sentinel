import sys

import pytest
from sentinel.models import AuditEvent, LoginAttempt, LoginSession, User
from sqlalchemy import select
from sqlalchemy.orm import Session

PASSWORD = "correct horse battery staple"


def test_cli_create_user_is_interactive_and_persists(settings, engine, monkeypatch, capsys):
    from sentinel.cli import main

    # Windows getpass reads the console, not subprocess stdin. Substitute only
    # that terminal boundary; exercise the real CLI, hashing, and database.
    answers = iter([PASSWORD, PASSWORD])
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(answers))
    monkeypatch.setattr(sys, "argv", ["sentinel.cli", "create-user", "admin"])
    assert main() == 0
    output = capsys.readouterr()
    assert "Created administrator 'admin'" in output.out
    assert PASSWORD not in output.out + output.err
    with Session(engine) as db:
        assert db.scalar(select(User.username)) == "admin"


def test_account_creation_hashes_password_and_normalizes_username(engine):
    from sentinel.accounts import create_user
    from sentinel.security import verify_password

    with Session(engine) as db:
        user = create_user(db, " Admin ", PASSWORD, now=1000)
        assert user.username == "admin"
        assert PASSWORD not in user.password_hash
        assert verify_password(PASSWORD, user.password_hash)
        assert not verify_password("wrong password", user.password_hash)
        assert db.scalar(select(AuditEvent.action)) == "account_created"
        with pytest.raises(ValueError, match="already exists"):
            create_user(db, "ADMIN", PASSWORD)


@pytest.mark.parametrize(
    "username,password",
    [
        ("bad username", PASSWORD),
        ("<script>", PASSWORD),
        ("a" * 65, PASSWORD),
        ("admin", "short"),
        ("admin", "x" * 129),
        ("admin", " " * 12),
    ],
)
def test_invalid_account_input_is_rejected(engine, username, password):
    from sentinel.accounts import create_user

    with Session(engine) as db, pytest.raises(ValueError):
        create_user(db, username, password)


def test_login_creates_hashed_persistent_session_and_logout_revokes(engine):
    from sentinel.accounts import authenticate, create_user, resolve_session, revoke_session

    with Session(engine) as db:
        create_user(db, "admin", PASSWORD, now=1000)
        token = authenticate(db, "ADMIN", PASSWORD, lifetime=3600, now=1001)
        assert token
        saved = db.scalar(select(LoginSession))
        assert saved.token_hash != token
        assert saved.expires_at == 4601
    with Session(engine) as db:
        user, login = resolve_session(db, token, now=1002)
        assert user.username == "admin"
        assert login.csrf_token
        assert resolve_session(db, token, now=4601) is None
        assert resolve_session(db, "forged", now=1002) is None
        revoke_session(db, token, now=1003)
        assert resolve_session(db, token, now=1004) is None
        assert db.scalars(select(AuditEvent.action).order_by(AuditEvent.id)).all() == [
            "account_created",
            "signed_in",
            "signed_out",
        ]


def test_invalid_credentials_are_throttled_and_window_expires(engine):
    from sentinel.accounts import LoginThrottled, authenticate, create_user

    with Session(engine) as db:
        create_user(db, "admin", PASSWORD)
        for _ in range(5):
            assert authenticate(db, "admin", "wrong", now=1000) is None
        with pytest.raises(LoginThrottled):
            authenticate(db, "admin", PASSWORD, now=1001)
        assert authenticate(db, "admin", PASSWORD, now=1301)
        assert db.scalar(select(LoginAttempt)) is None


def test_unknown_user_has_same_failure_and_throttling(engine):
    from sentinel.accounts import LoginThrottled, authenticate

    with Session(engine) as db:
        for _ in range(5):
            assert authenticate(db, "unknown", PASSWORD, now=1000) is None
        with pytest.raises(LoginThrottled):
            authenticate(db, "unknown", PASSWORD, now=1001)
        assert db.scalar(select(User)) is None
