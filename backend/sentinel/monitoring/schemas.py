import json
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["info", "low", "medium", "high", "critical"]


def utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("An explicit UTC offset is required")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class EventInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identity: str = Field(pattern=r"^[a-f0-9]{64}$")
    observed_at: datetime
    source: str = Field(min_length=1, max_length=128)
    category: Literal["windows_event", "inventory_baseline", "inventory_change", "collection_gap"]
    severity: Severity
    summary: str = Field(min_length=1, max_length=1000)
    evidence: dict

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value):
        utc(value)
        if value > datetime.now(UTC).replace(microsecond=0) + timedelta(days=1):
            raise ValueError("Event time is more than one day in the future")
        return value

    @field_validator("evidence")
    @classmethod
    def bounded_evidence(cls, value):
        fields = value.get("fields", {})
        if not isinstance(fields, dict) or any(not isinstance(v, str) for v in fields.values()):
            raise ValueError("Windows fields must be a mapping of names to original text values")
        if len(json.dumps(value).encode()) > 256_000:
            raise ValueError("Evidence exceeds 256 KB; cursor must not advance")
        return value


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host_id: str = Field(min_length=1, max_length=64)
    events: list[EventInput] = Field(default_factory=list, max_length=100)
    health: dict = Field(default_factory=dict)

    @field_validator("health")
    @classmethod
    def bounded_health(cls, value):
        if len(json.dumps(value).encode()) > 64_000:
            raise ValueError("Health exceeds 64 KB")
        return value


class PolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    retention_days: int = Field(default=30, ge=1, le=365)
    max_database_mb: int = Field(default=512, ge=16, le=8192)
    min_free_disk_mb: int = Field(default=128, ge=16, le=8192)
    failed_logon_threshold: int = Field(default=5, ge=2, le=100)
    failed_logon_window_seconds: int = Field(default=300, ge=30, le=3600)
