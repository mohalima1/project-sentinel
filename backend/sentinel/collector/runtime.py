import sqlite3
import time

from sentinel.collector.spool import QueueFull
from sentinel.collector.windows import INVENTORIES, LOGS


def collect_source(spool, source, reader, health):
    prior = health.get(source, {})
    cursor = spool.state("log:" + source) if source in LOGS else None
    result = reader(source, cursor)
    state = {
        "status": result["status"],
        "checked_at": int(time.time()),
        "last_success": prior.get("last_success"),
        "error": result.get("error"),
        "scope": result.get("scope"),
        "identity": result.get("identity"),
    }
    health[source] = state
    if result["status"] != "available":
        return
    if source in LOGS:
        spool.log_batch(source, result)
        state["cursor"] = spool.state("log:" + source)
    elif source in INVENTORIES:
        spool.snapshot(source, result["items"])
        state["items"] = len(result["items"])
    else:
        state["raw"] = result.get("raw", "")
        state["note"] = result.get("note", "")
    state["last_success"] = int(time.time())


def deliver(spool, send, health):
    pending = spool.pending()
    result = send({"host_id": spool.host_id, "events": pending, "health": health})
    expected = {event["identity"] for event in pending}
    if set(result.get("accepted", [])) != expected:
        raise OSError("Incomplete acknowledgement; original queue retained for replay")
    spool.ack(list(expected))
    return len(pending)


def collect_cycle(spool, sources, reader, send, health, stop_requested=None):
    for source in sources:
        if stop_requested and stop_requested():
            return
        try:
            collect_source(spool, source, reader, health["sources"])
        except (QueueFull, sqlite3.Error, OSError, ValueError) as exc:
            prior = health["sources"].get(source, {})
            health["sources"][source] = {**prior, "status": "blocked", "error": str(exc)[:500]}
            health["failures"] += 1
        health.update(
            queue_bytes=spool.queue_bytes(),
            queue_limit_bytes=spool.max_queue_bytes,
            spool_bytes=spool.path.stat().st_size,
            spool_limit_bytes=spool.max_spool_bytes,
            min_free_disk_bytes=spool.min_free_bytes,
            gaps=spool.state("gap_count") or 0,
            updated_at=int(time.time()),
        )
        # A slow later source must not hide progress of earlier sources. Windows
        # reads time out at 60s and HTTP at 20s, below the 120s stale threshold.
        try:
            deliver(spool, send, health)
            health["last_delivery"] = int(time.time())
            health["delivery_error"] = None
        except (OSError, ValueError, sqlite3.Error) as exc:
            health["delivery_error"] = str(exc)[:500]
            health["failures"] += 1
