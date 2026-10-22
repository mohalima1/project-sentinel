import argparse
import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from sentinel.collector.lock import collector_lock
from sentinel.collector.runtime import collect_cycle, deliver
from sentinel.collector.spool import Spool
from sentinel.collector.windows import SOURCES, read_source
from sentinel.config import Settings
from sentinel.monitoring.credentials import credential_path, load_credentials, provision


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise OSError("Collector refuses redirects to protect ingestion credentials")


def sender(url, credential):
    parsed = urlparse(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username
    ):
        raise ValueError("Collector backend must be a loopback HTTP URL")
    opener = build_opener(ProxyHandler({}), NoRedirect())

    def send(payload):
        request = Request(
            url.rstrip("/") + "/api/ingest",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + credential["token"],
            },
        )
        try:
            with opener.open(request, timeout=20) as response:
                return json.load(response)
        except HTTPError as exc:
            # Do not print telemetry, credentials or request headers.
            raise OSError(
                f"Backend rejected delivery (HTTP {exc.code}); local evidence retained"
            ) from exc

    return send


def save_health(path, health):
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(health, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def run(args):
    base = Path(args.data_dir).resolve()
    credential = load_credentials(
        Path(args.credential_file) if args.credential_file else base / "ingestion.json"
    )
    if not credential:
        raise ValueError("Run collector --provision in the backend data directory first")
    send = sender(args.url, credential)
    path = base / "collector" / "queue.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    health_path = path.with_name("health.json")
    try:
        health = json.loads(health_path.read_text())
    except FileNotFoundError:
        health = {"sources": {}, "failures": 0, "dropped_data": 0, "gaps": 0}
    backoff = 2
    with (
        collector_lock(path.with_suffix(".lock")),
        Spool(
            path,
            credential["host_id"],
            max_queue_bytes=args.queue_mb * 1024**2,
            max_spool_bytes=args.spool_mb * 1024**2,
            min_free_bytes=args.min_free_mb * 1024**2,
        ) as spool,
    ):
        while True:
            if args.stop_file and Path(args.stop_file).exists():
                return 0
            # Existing queue drains first so recovery from a full queue is possible.
            try:
                deliver(spool, send, health)
                health["delivery_error"] = None
                health["last_delivery"] = int(time.time())
                backoff = 2
            except (OSError, ValueError) as exc:
                health["delivery_error"] = str(exc)
                health["failures"] += 1
                backoff = min(60, backoff * 2)
            collect_cycle(
                spool,
                SOURCES,
                read_source,
                send,
                health,
                stop_requested=lambda: args.stop_file and Path(args.stop_file).exists(),
            )
            health.update(
                queue_bytes=spool.queue_bytes(),
                queue_limit_bytes=spool.max_queue_bytes,
                spool_bytes=path.stat().st_size,
                spool_limit_bytes=spool.max_spool_bytes,
                min_free_disk_bytes=spool.min_free_bytes,
                updated_at=int(time.time()),
            )
            health["gaps"] = spool.state("gap_count") or 0
            try:
                # Bounded drain per cycle; send updated heartbeat even if no events exist.
                for _ in range(20):
                    delivered = deliver(spool, send, health)
                    health["last_delivery"] = int(time.time())
                    health["delivery_error"] = None
                    if not delivered:
                        break
                health["queue_bytes"] = spool.queue_bytes()
                # Final heartbeat reports drained queue usage, not the pre-delivery value.
                deliver(spool, send, health)
            except (OSError, ValueError, sqlite3.Error) as exc:
                health["delivery_error"] = str(exc)[:500]
                health["failures"] += 1
            try:
                save_health(health_path, health)
            except OSError:
                print(
                    "Collector health could not be persisted: storage failure."
                    " Progress remains in queue.",
                    flush=True,
                )
            if args.once:
                return 1 if health.get("delivery_error") else 0
            time.sleep(
                max(args.interval, backoff) if health.get("delivery_error") else args.interval
            )


def main():
    parser = argparse.ArgumentParser(description="Separate read-only Sentinel Windows collector")
    parser.add_argument("--data-dir", default=str(Settings().database_path.parent))
    parser.add_argument("--url", default="http://127.0.0.1:8765")
    parser.add_argument(
        "--credential-file",
        help="Separate private credential location for the Windows service",
    )
    parser.add_argument("--stop-file", help="Private service stop marker; not a web control")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--provision", action="store_true")
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--queue-mb", type=int, default=64)
    parser.add_argument("--spool-mb", type=int, default=128)
    parser.add_argument("--min-free-mb", type=int, default=128)
    args = parser.parse_args()
    if (
        min(args.interval, args.queue_mb, args.spool_mb, args.min_free_mb) < 1
        or args.spool_mb < args.queue_mb
    ):
        parser.error("Positive limits required; spool limit must be at least queue limit")
    if args.provision:
        provision(credential_path(Path(args.data_dir).resolve() / "sentinel.db"))
        print("Private collector credential ready. No token is printed.")
        return 0
    try:
        return run(args)
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"Collector stopped: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
