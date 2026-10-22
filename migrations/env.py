from alembic import context
from sentinel.config import Settings
from sentinel.db import make_engine
from sentinel.models import Base
from sentinel.monitoring import models as monitoring_models  # noqa: F401

target_metadata = Base.metadata

if context.is_offline_mode():
    from sqlalchemy import URL

    context.configure(
        url=URL.create("sqlite", database=str(Settings().database_path)),
        target_metadata=target_metadata,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = make_engine(Settings().database_path)
    try:
        with engine.connect() as connection:
            context.configure(
                connection=connection, target_metadata=target_metadata, render_as_batch=True
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()
