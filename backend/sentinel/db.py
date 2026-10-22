from pathlib import Path

from sqlalchemy import URL, create_engine, event, text
from sqlalchemy.engine import Engine

SCHEMA_REVISION = "0002"


def make_engine(path: Path) -> Engine:
    path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        URL.create("sqlite", database=str(path)),
        connect_args={"check_same_thread": False, "timeout": 10, "autocommit": False},
    )

    @event.listens_for(engine, "connect")
    def configure_connection(connection, _record):
        # Python 3.12's explicit transactions require autocommit for this PRAGMA.
        connection.autocommit = True
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
        connection.autocommit = False

    return engine


def require_schema(engine: Engine) -> None:
    try:
        with engine.connect() as db:
            revision = db.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            if revision != SCHEMA_REVISION:
                raise ValueError("Unexpected schema revision")
    except Exception as exc:
        raise RuntimeError(
            "Database is not at the required migration. Run: uv run alembic upgrade head"
        ) from exc
