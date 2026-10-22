"""Per-installation credentials, provisioned locally, never through the browser."""

import json
import os
import secrets
import subprocess
import uuid
from pathlib import Path


def credential_path(database_path: Path) -> Path:
    return database_path.parent / "ingestion.json"


def load_credentials(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if len(value["token"]) < 32 or not value["host_id"]:
            raise ValueError("Invalid collector credentials")
        return value
    except FileNotFoundError:
        return None


def protect_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        # SID forms work on localized Windows. Include the current identity by SID.
        result = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True
        )
        import csv

        sid = next(csv.reader([result.stdout.strip()]))[1]
        subprocess.run(
            [
                "icacls",
                str(path),
                "/inheritance:r",
                "/grant:r",
                f"*{sid}:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ],
            capture_output=True,
            check=True,
        )
    else:
        path.chmod(0o700)


def provision(path: Path) -> dict:
    existing = load_credentials(path)
    if existing:
        return existing
    protect_directory(path.parent)
    value = {"host_id": str(uuid.uuid4()), "token": secrets.token_urlsafe(48)}
    # Exclusive creation prevents concurrent launchers replacing a live credential.
    try:
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        return load_credentials(path)
    if os.name != "nt":
        path.chmod(0o600)
    return value
