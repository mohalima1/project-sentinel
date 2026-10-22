import hashlib
import secrets
import time
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import ValidationError
from sqlalchemy import String, select, update
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import Session

from sentinel.models import AuditEvent
from sentinel.monitoring.credentials import credential_path, load_credentials
from sentinel.monitoring.detections import detect
from sentinel.monitoring.models import CollectorStatus, HostEvent, MonitoringPolicy
from sentinel.monitoring.schemas import Envelope, PolicyInput, Severity, utc
from sentinel.monitoring.storage import database_bytes, ensure_capacity, retain


def serialize_event(event, *, evidence=True):
    return {
        key: getattr(event, key)
        for key in (
            "id",
            "identity",
            "host_id",
            "observed_at",
            "received_at",
            "source",
            "category",
            "severity",
            "summary",
            "evidence",
        )
        if key != "evidence" or evidence
    }


def collection_status(db, settings):
    state = db.scalar(select(CollectorStatus))
    now = int(time.time())
    return {
        "connection": (
            "never_connected"
            if not state
            else "connected"
            if now - state.last_heartbeat < 120
            else "stale"
        ),
        "last_heartbeat": state.last_heartbeat if state else None,
        "last_ingestion": state.last_ingestion if state else None,
        "health": state.health if state else {},
        "database_bytes": database_bytes(settings.database_path),
        "message": "Collection health describes coverage, not whether the host is secure.",
    }


def router(settings, database_engine, database, authorized, check_csrf):
    routes = APIRouter()
    DB = Annotated[Session, Depends(database)]
    Auth = Annotated[tuple, Depends(authorized)]

    def ingestion_auth(authorization: Annotated[str | None, Header()] = None):
        credential = load_credentials(credential_path(settings.database_path))
        actual = hashlib.sha256((authorization or "").encode()).digest()
        expected = (
            hashlib.sha256(("Bearer " + credential["token"]).encode()).digest()
            if credential
            else b""
        )
        if not credential or not secrets.compare_digest(actual, expected):
            raise HTTPException(401, "Collector credential required.")
        return credential

    Credential = Annotated[dict, Depends(ingestion_auth)]

    @routes.post("/api/ingest")
    async def ingest(request: Request, credential: Credential):
        # Authenticate before parsing. Never buffer an unbounded body, including chunked requests.
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 2_000_000:
                raise HTTPException(413, "Batch exceeds 2 MB. Split delivery; retain local queue.")
        try:
            envelope = Envelope.model_validate_json(body)
        except (ValidationError, ValueError) as exc:
            raise HTTPException(422, "Invalid collector envelope: " + str(exc)[:300]) from exc
        if envelope.host_id != credential["host_id"]:
            raise HTTPException(403, "Collector host identity mismatch.")
        # This sync transaction is run off the event loop, just like FastAPI sync endpoints.
        from starlette.concurrency import run_in_threadpool

        return await run_in_threadpool(commit_envelope, envelope, len(body))

    def commit_envelope(envelope, body_bytes):
        with Session(database_engine) as db:
            db.execute(update(MonitoringPolicy).where(MonitoringPolicy.id == 1).values(id=1))
            policy = db.get(MonitoringPolicy, 1)
            retain(db, policy)
            ensure_capacity(db, settings.database_path, policy, body_bytes)
            inserted = 0
            now = int(time.time())
            for event in envelope.events:
                values = event.model_dump(exclude={"observed_at"})
                values.update(
                    host_id=envelope.host_id, observed_at=utc(event.observed_at), received_at=now
                )
                result = db.execute(
                    insert(HostEvent)
                    .values(**values)
                    .on_conflict_do_nothing(index_elements=["identity"])
                    .returning(HostEvent.id)
                ).scalar_one_or_none()
                if result is not None:
                    inserted += 1
                    detect(db, db.get(HostEvent, result), policy)
            retain(db, policy)
            state = db.get(CollectorStatus, envelope.host_id)
            if state is None:
                state = CollectorStatus(host_id=envelope.host_id, health={}, last_heartbeat=now)
                db.add(state)
            state.last_heartbeat = now
            if envelope.events:
                state.last_ingestion = now
            state.health = envelope.health
            db.commit()  # Acknowledgement must follow durable commit.
            return {"accepted": [e.identity for e in envelope.events], "inserted": inserted}

    @routes.get("/api/events")
    def events(
        db: DB,
        auth: Auth,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        before: Annotated[int | None, Query(ge=1)] = None,
        source: Annotated[str | None, Query(max_length=128)] = None,
        category: Annotated[str | None, Query(max_length=32)] = None,
        severity: Severity | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        q: Annotated[str | None, Query(max_length=200)] = None,
        changes_only: bool = False,
    ):
        query = select(HostEvent)
        if changes_only:
            query = query.where(
                (HostEvent.category == "inventory_change")
                | (
                    (HostEvent.category == "windows_event")
                    & HostEvent.evidence["event_id"]
                    .as_integer()
                    .in_([4732, 4733, 4697, 7045, 4698, 4702, 1102, 1116])
                )
            )
        for column, value in (
            (HostEvent.source, source),
            (HostEvent.category, category),
            (HostEvent.severity, severity),
        ):
            if value is not None:
                query = query.where(column == value)
        if before:
            query = query.where(HostEvent.id < before)
        try:
            if since:
                query = query.where(HostEvent.observed_at >= utc(since))
            if until:
                query = query.where(HostEvent.observed_at <= utc(until))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if q:
            query = query.where(
                HostEvent.summary.contains(q, autoescape=True)
                | HostEvent.evidence.cast(String).contains(q, autoescape=True)
            )
        rows = db.scalars(query.order_by(HostEvent.id.desc()).limit(limit + 1)).all()
        return {
            "events": [serialize_event(e, evidence=False) for e in rows[:limit]],
            "next_cursor": rows[limit - 1].id if len(rows) > limit else None,
        }

    @routes.get("/api/events/{event_id}")
    def event_detail(event_id: int, db: DB, auth: Auth):
        event = db.get(HostEvent, event_id)
        if event is None:
            raise HTTPException(404, "Event not found or expired under retention.")
        return serialize_event(event)

    @routes.get("/api/collection")
    def collection(db: DB, auth: Auth):
        return collection_status(db, settings)

    @routes.get("/api/settings")
    def get_settings(db: DB, auth: Auth):
        policy = db.get(MonitoringPolicy, 1)
        return {key: getattr(policy, key) for key in PolicyInput.model_fields}

    @routes.put("/api/settings")
    def put_settings(
        payload: PolicyInput,
        db: DB,
        auth: Auth,
        x_csrf_token: Annotated[str | None, Header()] = None,
    ):
        check_csrf(x_csrf_token, auth[1].csrf_token)
        username = auth[0].username
        db.rollback()
        db.execute(update(MonitoringPolicy).where(MonitoringPolicy.id == 1).values(id=1))
        policy = db.get(MonitoringPolicy, 1)
        for key, value in payload.model_dump().items():
            setattr(policy, key, value)
        retain(db, policy)
        db.add(
            AuditEvent(username=username, action="settings_changed", created_at=int(time.time()))
        )
        db.commit()
        return payload

    return routes
