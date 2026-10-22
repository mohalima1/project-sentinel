"""Ephemeral access granted only by the local launcher, never a public bypass."""

import secrets
import time
from threading import Lock

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from sentinel.models import AuditEvent, LoginSession, User
from sentinel.security import token_hash


class LocalAccess:
    def __init__(self):
        self.token = secrets.token_urlsafe(32)
        self.expires_at = time.monotonic() + 120
        self._used = False
        self._lock = Lock()

    def exchange(self, supplied: str, db: Session, lifetime: int) -> str | None:
        with self._lock:
            if (
                self._used
                or time.monotonic() >= self.expires_at
                or not secrets.compare_digest(supplied.encode(), self.token.encode())
            ):
                return None
            now = int(time.time())
            db.rollback()
            db.execute(delete(LoginSession).where(LoginSession.expires_at <= now))
            # Reserved identity cannot be created through the account CLI.
            user = db.scalar(select(User).where(User.username == "@local"))
            if user is None:
                user = User(username="@local", password_hash="local-only", created_at=now)
                db.add(user)
                db.flush()
            token = secrets.token_urlsafe(32)
            db.add(
                LoginSession(
                    token_hash=token_hash(token),
                    user_id=user.id,
                    csrf_token=secrets.token_urlsafe(32),
                    created_at=now,
                    expires_at=now + lifetime,
                )
            )
            db.add(AuditEvent(username="@local", action="signed_in", created_at=now))
            db.commit()
            self._used = True
            return token
