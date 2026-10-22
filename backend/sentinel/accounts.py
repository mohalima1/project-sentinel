import re
import secrets
import time

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from sentinel.models import AuditEvent, LoginAttempt, LoginSession, User
from sentinel.security import hash_password, token_hash, verify_password

DUMMY_HASH = hash_password(secrets.token_urlsafe(32))
LOGIN_WINDOW = 300
MAX_ATTEMPTS = 5


class LoginThrottled(Exception):
    pass


def create_user(db: Session, username: str, password: str, *, now: int | None = None) -> User:
    username = username.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", username):
        raise ValueError("Username must be 1-64 letters, numbers, dots, underscores or hyphens.")
    if not 12 <= len(password) <= 128 or not password.strip():
        raise ValueError("Password must contain 12-128 characters and cannot be only spaces.")
    timestamp = int(time.time()) if now is None else now
    user = User(username=username, password_hash=hash_password(password), created_at=timestamp)
    db.add(user)
    db.add(AuditEvent(username=username, action="account_created", created_at=timestamp))
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("That username already exists.") from exc
    db.refresh(user)
    return user


def authenticate(
    db: Session, username: str, password: str, *, lifetime: int = 28800, now: int | None = None
) -> str | None:
    timestamp = int(time.time()) if now is None else now
    username = username.strip().lower()
    db.rollback()  # Authentication owns its transactions; release any prior read snapshot.
    # Reserve the writer before counting; parallel failures cannot read an old
    # counter. The same policy applies to nonexistent accounts.
    db.execute(delete(LoginAttempt).where(LoginAttempt.created_at <= timestamp - LOGIN_WINDOW))
    db.add(LoginAttempt(username=username, created_at=timestamp))
    db.flush()
    attempts = db.scalar(
        select(func.count()).select_from(LoginAttempt).where(LoginAttempt.username == username)
    )
    if attempts > MAX_ATTEMPTS:
        db.commit()
        raise LoginThrottled
    user = db.scalar(select(User).where(User.username == username))
    user_id = user.id if user else None
    encoded = user.password_hash if user else DUMMY_HASH
    db.commit()  # Never hold a database transaction during the expensive KDF.
    for _ in range(3):
        valid = verify_password(password, encoded)
        upgraded = hash_password(password) if valid and len(encoded.split("$")) == 3 else None
        # Acquire the writer reservation before reading state used by this write.
        db.execute(delete(LoginSession).where(LoginSession.expires_at <= timestamp))
        user = db.get(User, user_id, populate_existing=True) if user_id is not None else None
        if not valid or user is None or user.password_hash == encoded:
            break
        # Another login may have upgraded a legacy hash. Reverify the new value
        # outside the transaction; a genuine password change must still reject.
        encoded = user.password_hash
        db.rollback()
    else:
        return None  # State kept changing; never issue a session from a stale hash.
    if not valid or user is None:
        db.add(AuditEvent(username=username, action="sign_in_failed", created_at=timestamp))
        db.commit()
        return None
    token = secrets.token_urlsafe(32)
    if upgraded:
        user.password_hash = upgraded
    db.execute(delete(LoginAttempt).where(LoginAttempt.username == username))
    db.add(
        LoginSession(
            token_hash=token_hash(token),
            user_id=user.id,
            csrf_token=secrets.token_urlsafe(32),
            created_at=timestamp,
            expires_at=timestamp + lifetime,
        )
    )
    db.add(AuditEvent(username=username, action="signed_in", created_at=timestamp))
    db.commit()
    return token


def resolve_session(
    db: Session, token: str, *, now: int | None = None
) -> tuple[User, LoginSession] | None:
    if not token or len(token) > 128:
        return None
    timestamp = int(time.time()) if now is None else now
    login = db.get(LoginSession, token_hash(token))
    if login is None or login.expires_at <= timestamp:
        return None
    user = db.get(User, login.user_id)
    return (user, login) if user else None


def revoke_session(db: Session, token: str, *, now: int | None = None) -> None:
    timestamp = int(time.time()) if now is None else now
    db.rollback()
    db.execute(delete(LoginSession).where(LoginSession.expires_at <= timestamp))
    resolved = resolve_session(db, token, now=timestamp)
    if resolved:
        user, login = resolved
        db.delete(login)
        db.add(AuditEvent(username=user.username, action="signed_out", created_at=timestamp))
    db.commit()
