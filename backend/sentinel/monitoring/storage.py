import shutil
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import delete, text, update
from sqlalchemy.orm import Session

from sentinel.models import AuditEvent, LoginAttempt, LoginSession
from sentinel.monitoring.models import Alert, HostEvent, MonitoringPolicy
from sentinel.monitoring.schemas import utc


class StorageFull(Exception):
    pass


def available_bytes(path: Path) -> int:
    return shutil.disk_usage(path.parent).free


def database_bytes(path: Path) -> int:
    return sum(p.stat().st_size for p in [path, Path(str(path) + "-wal")] if p.exists())


def ensure_capacity(db, path, policy, incoming_bytes=0):
    page_count = db.execute(text("PRAGMA page_count")).scalar_one()
    free_pages = db.execute(text("PRAGMA freelist_count")).scalar_one()
    page_size = db.execute(text("PRAGMA page_size")).scalar_one()
    # SQLite enforces a physical file growth ceiling even if an estimate is low.
    pages = max(page_count, policy.max_database_mb * 1024**2 // page_size)
    db.connection().exec_driver_sql(f"PRAGMA max_page_count={pages}")
    # Conservative allowance for indexes and transaction journal, including reused pages.
    projected = (page_count - free_pages) * page_size + incoming_bytes * 4 + 64 * 1024
    if projected > policy.max_database_mb * 1024**2:
        raise StorageFull(
            "Database limit reached. Increase limit or shorten retention; queue retained."
        )
    if available_bytes(path) < policy.min_free_disk_mb * 1024**2 + incoming_bytes * 4:
        raise StorageFull("Low free disk space. Ingestion paused; collector queue retained.")


def retain(db, policy):
    cutoff = utc(datetime.now(UTC) - timedelta(days=policy.retention_days))
    # Alert evidence cascades with events. Alerts expire on their last triggering event.
    db.execute(delete(Alert).where(Alert.last_seen < cutoff))
    db.execute(delete(HostEvent).where(HostEvent.observed_at < cutoff))
    now = int(time.time())
    db.execute(delete(AuditEvent).where(AuditEvent.created_at < now - 90 * 86400))
    db.execute(delete(LoginAttempt).where(LoginAttempt.created_at < now - 86400))
    db.execute(delete(LoginSession).where(LoginSession.expires_at < now))


def maintenance(engine):
    with Session(engine) as db:
        db.execute(update(MonitoringPolicy).where(MonitoringPolicy.id == 1).values(id=1))
        retain(db, db.get(MonitoringPolicy, 1))
        db.commit()
