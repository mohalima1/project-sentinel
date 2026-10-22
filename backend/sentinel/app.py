import asyncio
import secrets
import time
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from sentinel import __version__
from sentinel.accounts import (
    LoginThrottled,
    authenticate,
    resolve_session,
    revoke_session,
)
from sentinel.config import ROOT, Settings
from sentinel.db import SCHEMA_REVISION, make_engine, require_schema
from sentinel.local_access import LocalAccess
from sentinel.models import AuditEvent, LoginSession, User
from sentinel.monitoring.alerts_api import alerts_router
from sentinel.monitoring.api import collection_status
from sentinel.monitoring.api import router as monitoring_router
from sentinel.monitoring.storage import StorageFull, maintenance

SESSION_COOKIE = "sentinel_session"
CSRF_COOKIE = "sentinel_login_csrf"


class LoginInput(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class LocalInput(BaseModel):
    token: str = Field(min_length=1, max_length=128)


def check_csrf(actual: str | None, expected: str | None) -> None:
    if (
        not actual
        or not expected
        or not secrets.compare_digest(actual.encode("utf-8"), expected.encode("utf-8"))
    ):
        raise HTTPException(403, "Request verification failed. Reload and try again.")


def create_app(
    settings: Settings | None = None, *, local_access: LocalAccess | None = None
) -> FastAPI:
    settings = settings or Settings()
    engine = make_engine(settings.database_path)
    started_at = time.monotonic()

    @asynccontextmanager
    async def lifespan(_app):
        stop_maintenance = asyncio.Event()

        async def retention_loop():
            while not stop_maintenance.is_set():
                try:
                    await asyncio.to_thread(maintenance, engine)
                    application.state.maintenance_error = None
                except SQLAlchemyError:
                    application.state.maintenance_error = (
                        "Retention maintenance failed; check database storage and permissions."
                    )
                try:
                    await asyncio.wait_for(stop_maintenance.wait(), timeout=60)
                except TimeoutError:
                    pass

        task = None
        try:
            require_schema(engine)
            application.state.maintenance_error = None
            task = asyncio.create_task(retention_loop())
            yield
        finally:
            if task:
                stop_maintenance.set()
                await task
            engine.dispose()

    application = FastAPI(
        title="Project Sentinel",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @application.middleware("http")
    async def request_security(request: Request, call_next):
        origin = request.headers.get("origin")
        if request.method not in {"GET", "HEAD", "OPTIONS"} and (
            origin is not None and origin != str(request.base_url).rstrip("/")
        ):
            response = JSONResponse({"detail": "Foreign origin is not permitted."}, 403)
        else:
            response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'; object-src 'none'"
        )
        return response

    application.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]"]
    )

    @application.exception_handler(SQLAlchemyError)
    async def database_unavailable(_request, _exc):
        return JSONResponse({"detail": "Database unavailable. Check the backend and retry."}, 503)

    @application.exception_handler(StorageFull)
    async def storage_full(_request, exc):
        return JSONResponse({"detail": str(exc)}, 507)

    def database():
        with Session(engine) as db:
            yield db

    DB = Annotated[Session, Depends(database)]

    def authorized(request: Request, db: DB) -> tuple[User, LoginSession]:
        resolved = resolve_session(db, request.cookies.get(SESSION_COOKIE, ""))
        if resolved is None:
            raise HTTPException(401, "Sign in to continue.")
        return resolved

    Auth = Annotated[tuple[User, LoginSession], Depends(authorized)]

    monitoring = monitoring_router(settings, engine, database, authorized, check_csrf)
    application.include_router(monitoring)
    application.include_router(alerts_router(database, authorized, check_csrf))

    def session_body(user: User, login: LoginSession) -> dict:
        return {
            "username": user.username,
            "csrf_token": login.csrf_token,
            "expires_at": login.expires_at,
        }

    @application.get("/healthz")
    def health(db: DB):
        db.execute(text("SELECT 1"))
        return {"status": "ok"}

    @application.get("/api/auth/csrf")
    def login_csrf(response: Response):
        token = secrets.token_urlsafe(32)
        response.set_cookie(
            CSRF_COOKIE,
            token,
            max_age=600,
            httponly=True,
            secure=settings.secure_cookies,
            samesite="strict",
        )
        return {"csrf_token": token}

    @application.post("/api/auth/login")
    def login(
        payload: LoginInput,
        request: Request,
        response: Response,
        db: DB,
        x_csrf_token: Annotated[str | None, Header()] = None,
    ):
        check_csrf(x_csrf_token, request.cookies.get(CSRF_COOKIE))
        try:
            token = authenticate(
                db, payload.username, payload.password, lifetime=settings.session_seconds
            )
        except LoginThrottled as exc:
            raise HTTPException(
                429,
                "Too many sign-in attempts. Try again in 5 minutes.",
                headers={"Retry-After": "300"},
            ) from exc
        if token is None:
            raise HTTPException(401, "Invalid username or password.")
        # Revoke an existing browser session when signing in again.
        previous = request.cookies.get(SESSION_COOKIE)
        if previous:
            revoke_session(db, previous)
        response.set_cookie(
            SESSION_COOKIE,
            token,
            max_age=settings.session_seconds,
            httponly=True,
            secure=settings.secure_cookies,
            samesite="strict",
        )
        response.delete_cookie(CSRF_COOKIE, httponly=True, samesite="strict")
        user, saved_session = resolve_session(db, token)
        return session_body(user, saved_session)

    @application.get("/api/auth/session")
    def current_session(auth: Auth):
        return session_body(*auth)

    @application.post("/api/auth/local")
    def local_login(payload: LocalInput, response: Response, db: DB):
        token = (
            local_access.exchange(payload.token, db, settings.session_seconds)
            if local_access
            else None
        )
        if token is None:
            raise HTTPException(
                401,
                "Local access link expired or already used. Restart Sentinel to open a new link.",
            )
        response.set_cookie(
            SESSION_COOKIE,
            token,
            max_age=settings.session_seconds,
            httponly=True,
            secure=settings.secure_cookies,
            samesite="strict",
        )
        return session_body(*resolve_session(db, token))

    @application.post("/api/auth/logout", status_code=204)
    def logout(
        request: Request,
        response: Response,
        db: DB,
        auth: Auth,
        x_csrf_token: Annotated[str | None, Header()] = None,
    ):
        check_csrf(x_csrf_token, auth[1].csrf_token)
        revoke_session(db, request.cookies.get(SESSION_COOKIE, ""))
        response.delete_cookie(SESSION_COOKIE, httponly=True, samesite="strict")

    @application.get("/api/status")
    def status(db: DB, auth: Auth):
        now = int(time.time())
        collection = collection_status(db, settings)
        return {
            "version": __version__,
            "server_time": now,
            "uptime_seconds": int(time.monotonic() - started_at),
            "database": {
                "status": "connected",
                "revision": SCHEMA_REVISION,
                "users": db.scalar(select(func.count()).select_from(User)),
                "active_sessions": db.scalar(
                    select(func.count())
                    .select_from(LoginSession)
                    .where(LoginSession.expires_at > now)
                ),
                "maintenance_error": getattr(application.state, "maintenance_error", None),
            },
            "telemetry": {
                "status": "unavailable"
                if collection["connection"] == "never_connected"
                else collection["connection"],
                "reason": "No collector connected yet."
                if collection["connection"] == "never_connected"
                else (
                    "Check collection health for source coverage and gaps. "
                    "Collection is not a security assessment."
                ),
            },
            "host_controls_enabled": False,
        }

    @application.get("/api/audit")
    def audit(db: DB, auth: Auth):
        events = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(50)).all()
        return {
            "events": [
                {
                    "id": event.id,
                    "username": event.username,
                    "action": event.action,
                    "created_at": event.created_at,
                }
                for event in events
            ]
        }

    dist = ROOT / "frontend" / "dist"
    if (dist / "assets").is_dir():
        application.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @application.get("/", include_in_schema=False)
    def frontend():
        if not (dist / "index.html").is_file():
            raise HTTPException(503, "Build dashboard first: npm.cmd --prefix frontend run build")
        return FileResponse(dist / "index.html")

    return application


app = create_app()
