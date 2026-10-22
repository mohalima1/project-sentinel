from sqlalchemy import JSON, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from sentinel.models import Base


class HostEvent(Base):
    __tablename__ = "host_events"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    identity: Mapped[str] = mapped_column(String(64), unique=True)
    host_id: Mapped[str] = mapped_column(String(64))
    observed_at: Mapped[str] = mapped_column(String(32), index=True)
    received_at: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    summary: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON)
    __table_args__ = ({"sqlite_autoincrement": True},)


class CollectorStatus(Base):
    __tablename__ = "collector_status"
    host_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_heartbeat: Mapped[int] = mapped_column(Integer)
    last_ingestion: Mapped[int | None] = mapped_column(Integer)
    health: Mapped[dict] = mapped_column(JSON)


class MonitoringPolicy(Base):
    __tablename__ = "monitoring_policy"
    id: Mapped[int] = mapped_column(primary_key=True)
    retention_days: Mapped[int] = mapped_column(Integer, default=30)
    max_database_mb: Mapped[int] = mapped_column(Integer, default=512)
    min_free_disk_mb: Mapped[int] = mapped_column(Integer, default=128)
    failed_logon_threshold: Mapped[int] = mapped_column(Integer, default=5)
    failed_logon_window_seconds: Mapped[int] = mapped_column(Integer, default=300)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    rule: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[str] = mapped_column(String(32))
    last_seen: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(16), default="new")
    explanation: Mapped[dict] = mapped_column(JSON)
    __table_args__ = ({"sqlite_autoincrement": True},)


class AlertEvidence(Base):
    __tablename__ = "alert_evidence"
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[int] = mapped_column(
        ForeignKey("host_events.id", ondelete="CASCADE"), primary_key=True
    )


class Suppression(Base):
    __tablename__ = "suppressions"
    rule: Mapped[str] = mapped_column(String(64), primary_key=True)
    until: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)


Index("ix_host_events_source_category_id", HostEvent.source, HostEvent.category, HostEvent.id)
