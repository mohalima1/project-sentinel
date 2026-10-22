import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(os.environ.get("SENTINEL_RESOURCE_ROOT", Path(__file__).resolve().parents[2])).resolve()


@dataclass(frozen=True)
class Settings:
    database_path: Path = field(
        default_factory=lambda: (
            Path(os.environ.get("SENTINEL_DATABASE_PATH", str(ROOT / "data" / "sentinel.db")))
            .expanduser()
            .resolve()
        )
    )
    session_seconds: int = 8 * 60 * 60
    secure_cookies: bool = False  # Loopback HTTP development; enable for HTTPS deployment.

    def __post_init__(self):
        object.__setattr__(self, "database_path", self.database_path.expanduser().resolve())
