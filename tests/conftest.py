import pytest
from alembic import command
from alembic.config import Config
from sentinel.config import ROOT, Settings
from sentinel.db import make_engine


@pytest.fixture
def settings(tmp_path, monkeypatch):
    path = tmp_path / "sentinel.db"
    monkeypatch.setenv("SENTINEL_DATABASE_PATH", str(path))
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    return Settings(database_path=path)


@pytest.fixture
def engine(settings):
    db_engine = make_engine(settings.database_path)
    yield db_engine
    db_engine.dispose()
