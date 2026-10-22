"""Installed per-user dashboard entry point; must run without elevation."""
import ctypes
import json
import os
from pathlib import Path

root = Path(__file__).resolve().parents[1]
if ctypes.windll.shell32.IsUserAnAdmin():
    raise SystemExit("Open Sentinel from a normal Windows session; the web backend must not run elevated.")
config = json.loads((root / "installation.json").read_text(encoding="utf-8-sig"))
os.environ["SENTINEL_DATABASE_PATH"] = str(Path(config["backend_data"]) / "sentinel.db")
os.environ["SENTINEL_RESOURCE_ROOT"] = str(root / "app")
os.environ["SENTINEL_LISTEN_PORT"] = "8765"
os.environ["SENTINEL_COLLECTOR_DISABLED"] = "1"
from sentinel.launch import main  # noqa: E402

raise SystemExit(main())
