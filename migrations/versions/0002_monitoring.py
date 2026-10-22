"""Windows monitoring evidence, collector health, alerts and storage policy.

Foundation tables are intentionally untouched, preserving users and sessions.
"""

from alembic import op
from sentinel.monitoring.models import (
    Alert,
    AlertEvidence,
    CollectorStatus,
    HostEvent,
    MonitoringPolicy,
    Suppression,
)

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    for model in (HostEvent, CollectorStatus, MonitoringPolicy, Alert, AlertEvidence, Suppression):
        model.__table__.create(op.get_bind())
    op.bulk_insert(
        MonitoringPolicy.__table__,
        [
            {
                "id": 1,
                "retention_days": 30,
                "max_database_mb": 512,
                "min_free_disk_mb": 128,
                "failed_logon_threshold": 5,
                "failed_logon_window_seconds": 300,
            }
        ],
    )


def downgrade():
    for model in (Suppression, AlertEvidence, Alert, MonitoringPolicy, CollectorStatus, HostEvent):
        model.__table__.drop(op.get_bind())
