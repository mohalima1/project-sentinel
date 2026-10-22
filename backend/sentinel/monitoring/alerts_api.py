import time
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from sentinel.models import AuditEvent
from sentinel.monitoring.detections import RULES, serialize_alert
from sentinel.monitoring.models import Alert, MonitoringPolicy, Suppression

InvestigationState = Literal["new", "investigating", "resolved", "false_positive"]


class StateInput(BaseModel):
    state: InvestigationState


class SuppressionInput(BaseModel):
    seconds: int = Field(ge=60, le=7 * 86400)
    reason: str = Field(min_length=3, max_length=300)


def alerts_router(database, authorized, check_csrf):
    routes = APIRouter()
    DB = Annotated[Session, Depends(database)]
    Auth = Annotated[tuple, Depends(authorized)]

    def reserve(db):
        db.rollback()
        db.execute(update(MonitoringPolicy).where(MonitoringPolicy.id == 1).values(id=1))

    @routes.get("/api/alerts")
    def alerts(
        db: DB,
        auth: Auth,
        state: InvestigationState | None = None,
        before: Annotated[int | None, Query(ge=1)] = None,
        limit: Annotated[int, Query(ge=1, le=50)] = 20,
    ):
        query = select(Alert)
        if state:
            query = query.where(Alert.state == state)
        if before:
            query = query.where(Alert.id < before)
        rows = db.scalars(query.order_by(Alert.id.desc()).limit(limit + 1)).all()
        return {
            "alerts": [
                {
                    key: getattr(row, key)
                    for key in (
                        "id",
                        "rule",
                        "severity",
                        "title",
                        "first_seen",
                        "last_seen",
                        "state",
                        "explanation",
                    )
                }
                for row in rows[:limit]
            ],
            "next_cursor": rows[limit - 1].id if len(rows) > limit else None,
        }

    @routes.get("/api/alerts/{alert_id}")
    def alert_detail(alert_id: int, db: DB, auth: Auth):
        alert = db.get(Alert, alert_id)
        if alert is None:
            raise HTTPException(404, "Alert not found or expired under retention.")
        return serialize_alert(db, alert)

    @routes.patch("/api/alerts/{alert_id}")
    def change_state(
        alert_id: int,
        payload: StateInput,
        db: DB,
        auth: Auth,
        x_csrf_token: Annotated[str | None, Header()] = None,
    ):
        check_csrf(x_csrf_token, auth[1].csrf_token)
        username = auth[0].username
        reserve(db)
        alert = db.get(Alert, alert_id)
        if not alert:
            raise HTTPException(404, "Alert not found or expired under retention.")
        alert.state = payload.state
        db.add(
            AuditEvent(
                username=username,
                action=f"alert_{alert_id}_{payload.state}",
                created_at=int(time.time()),
            )
        )
        db.commit()
        return {"id": alert_id, "state": payload.state}

    @routes.get("/api/suppressions")
    def suppressions(db: DB, auth: Auth):
        rows = db.scalars(select(Suppression).where(Suppression.until > int(time.time()))).all()
        return {
            "suppressions": [{"rule": r.rule, "until": r.until, "reason": r.reason} for r in rows],
            "rules": [{"id": key, **value} for key, value in RULES.items()],
        }

    @routes.put("/api/suppressions/{rule}")
    def suppress(
        rule: str,
        payload: SuppressionInput,
        db: DB,
        auth: Auth,
        x_csrf_token: Annotated[str | None, Header()] = None,
    ):
        check_csrf(x_csrf_token, auth[1].csrf_token)
        if rule not in RULES:
            raise HTTPException(404, "Unknown detection rule.")
        username = auth[0].username
        reserve(db)
        row = db.get(Suppression, rule) or Suppression(rule=rule)
        row.until, row.reason = int(time.time()) + payload.seconds, payload.reason
        db.add(row)
        db.add(
            AuditEvent(
                username=username, action="rule_suppressed:" + rule, created_at=int(time.time())
            )
        )
        db.commit()
        return {"rule": rule, "until": row.until, "reason": row.reason}

    @routes.delete("/api/suppressions/{rule}", status_code=204)
    def unsuppress(
        rule: str, db: DB, auth: Auth, x_csrf_token: Annotated[str | None, Header()] = None
    ):
        check_csrf(x_csrf_token, auth[1].csrf_token)
        username = auth[0].username
        reserve(db)
        row = db.get(Suppression, rule)
        if row:
            db.delete(row)
            db.add(
                AuditEvent(
                    username=username,
                    action="rule_unsuppressed:" + rule,
                    created_at=int(time.time()),
                )
            )
        db.commit()

    return routes
