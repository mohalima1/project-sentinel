import hashlib
import json
import shutil
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree as ET

from sentinel.monitoring.schemas import EventInput, utc


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def free_bytes(path):
    return shutil.disk_usage(path.parent).free


class QueueFull(Exception):
    pass


class Spool:
    def __init__(
        self,
        path: Path,
        host_id: str,
        *,
        max_queue_bytes=64 * 1024**2,
        max_spool_bytes=128 * 1024**2,
        min_free_bytes=128 * 1024**2,
    ):
        self.path, self.host_id = path, host_id
        self.max_queue_bytes, self.min_free_bytes = max_queue_bytes, min_free_bytes
        self.max_spool_bytes = max_spool_bytes
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, isolation_level=None, timeout=1)
        try:
            self.db.execute("PRAGMA synchronous=FULL")
            size = self.db.execute("PRAGMA page_size").fetchone()[0]
            # Reserve a second database worth of space for the rollback journal.
            pages = max(8, (max_spool_bytes - 8192) // 2 // size)
            self.db.execute(f"PRAGMA max_page_count={pages}")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS queue (seq INTEGER PRIMARY KEY AUTOINCREMENT,
                  identity TEXT UNIQUE NOT NULL, payload TEXT NOT NULL, bytes INTEGER NOT NULL);
            """)
            if self.state("host") not in (None, host_id):
                raise ValueError(
                    "Spool belongs to a different host; do not replace installation credentials"
                )
            self.save("host", host_id)
        except BaseException:
            self.db.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.db.close()

    def state(self, key):
        row = self.db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def save(self, key, value):
        self.db.execute(
            "INSERT INTO state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, encode(value)),
        )

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if free_bytes(self.path) < self.min_free_bytes:
                raise QueueFull("Low free disk space; collection paused without advancing progress")
            yield
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def enqueue(self, event):
        EventInput.model_validate(event)  # Poison evidence cannot advance progress.
        payload = encode(event)
        size = len(payload.encode())
        used = self.queue_bytes()
        if used + size > self.max_queue_bytes:
            raise QueueFull(
                "Queue full; collection paused, progress unchanged, no queued evidence discarded"
            )
        inserted = self.db.execute(
            "INSERT OR IGNORE INTO queue(identity,payload,bytes) VALUES (?,?,?)",
            (event["identity"], payload, size),
        )
        if inserted.rowcount and event["category"] == "collection_gap":
            self.save("gap_count", (self.state("gap_count") or 0) + 1)

    def queue_bytes(self):
        return self.db.execute("SELECT COALESCE(SUM(bytes),0) FROM queue").fetchone()[0]

    def pending(self, limit=100):
        result, size = [], 0
        for payload, n in self.db.execute(
            "SELECT payload,bytes FROM queue ORDER BY seq LIMIT ?", (limit,)
        ):
            if size + n > 1_700_000:
                break
            result.append(json.loads(payload))
            size += n
        return result

    def ack(self, identities):
        with self.db:
            self.db.executemany(
                "DELETE FROM queue WHERE identity=?", [(key,) for key in identities]
            )

    def event(self, source, category, summary, evidence, key, *, observed_at=None, severity="info"):
        return {
            "identity": digest(self.host_id + ":" + source + ":" + key),
            "observed_at": observed_at or utc(datetime.now(UTC)),
            "source": source,
            "category": category,
            "severity": severity,
            "summary": summary,
            "evidence": evidence,
        }

    def snapshot(self, source, items):
        now = utc(datetime.now(UTC))
        with self.transaction():
            previous = self.state("snapshot:" + source)
            revision = previous["revision"] + 1 if previous else 1
            old = previous["items"] if previous else {}
            if previous is None:
                # Keep each original baseline part below the ingestion evidence limit.
                chunks, chunk = [], {}
                for key, value in sorted(items.items()):
                    if len(encode({**chunk, key: value})) > 160_000 and chunk:
                        chunks.append(chunk)
                        chunk = {}
                    chunk[key] = value
                chunks.append(chunk)
                for part, chunk in enumerate(chunks):
                    self.enqueue(
                        self.event(
                            source,
                            "inventory_baseline",
                            f"Initial {source} baseline: {len(items)} existing items"
                            f" (part {part + 1}/{len(chunks)})",
                            {
                                "initial_baseline": True,
                                "items": chunk,
                                "count": len(items),
                                "part": part + 1,
                                "parts": len(chunks),
                            },
                            f"baseline:{part}",
                            observed_at=now,
                        )
                    )
            else:
                for key in sorted(old.keys() | items.keys()):
                    before, after = old.get(key), items.get(key)
                    if before == after:
                        continue
                    kind = "added" if before is None else "removed" if after is None else "modified"
                    evidence = {
                        "item": key,
                        "change": kind,
                        "before": before,
                        "after": after,
                        "previous_snapshot_at": previous["observed_at"],
                        "current_snapshot_at": now,
                        "timing": "Observed between snapshots; exact change time is unknown.",
                    }
                    self.enqueue(
                        self.event(
                            source,
                            "inventory_change",
                            f"{source}: {key} {kind}",
                            evidence,
                            f"snapshot:{revision}:{key}",
                            observed_at=now,
                        )
                    )
            self.save(
                "snapshot:" + source, {"items": items, "revision": revision, "observed_at": now}
            )

    def log_batch(self, source, batch):
        with self.transaction():
            cursor = self.state("log:" + source)
            oldest, newest = batch["oldest"], batch["newest"]
            if batch["events"]:
                # The log may roll over after the reader obtained oldest metadata.
                first_record = parse_xml(batch["events"][0])[2]
                oldest = max(oldest, first_record)
            if batch.get("reset"):
                self.enqueue(
                    self.event(
                        source,
                        "collection_gap",
                        "Log reset or record reuse observed",
                        {
                            "reason": (
                                "Log clearing/reset or replacement;"
                                " activity during the gap may be missing."
                            ),
                            "previous_cursor": cursor,
                            "oldest": oldest,
                            "newest": newest,
                        },
                        "reset:" + encode(cursor) + ":" + encode(batch["events"][:1]),
                        severity="medium",
                    )
                )
                cursor = None
            elif cursor and oldest > cursor["record"] + 1:
                self.enqueue(
                    self.event(
                        source,
                        "collection_gap",
                        "Log records expired before collection",
                        {
                            "missing_from": cursor["record"] + 1,
                            "missing_until": oldest - 1,
                            "reason": (
                                "Source rollover or clearing;"
                                " missing evidence cannot be recovered here."
                            ),
                        },
                        f"gap:{cursor['record']}:{oldest}",
                        severity="medium",
                    )
                )
            elif cursor is None:
                self.enqueue(
                    self.event(
                        source,
                        "collection_gap",
                        "Initial log collection boundary",
                        {
                            "initial_boundary": True,
                            "oldest_available": oldest,
                            "newest_at_start": newest,
                            "start_record": batch.get("start_record", oldest),
                            "reason": (
                                "First collection imports at most the latest 200 records per log;"
                                " earlier history is not assessed."
                            ),
                        },
                        "initial-log-boundary",
                    )
                )
            for raw in batch["events"]:
                evidence, observed_at, record, severity = parse_xml(raw)
                self.enqueue(
                    self.event(
                        source,
                        "windows_event",
                        f"{evidence['provider']} event {evidence['event_id']} (record {record})",
                        evidence,
                        "xml:" + digest(raw),
                        observed_at=observed_at,
                        severity=severity,
                    )
                )
                cursor = {"record": record, "anchor_hash": digest(raw), "observed_at": observed_at}
            if cursor is None:
                cursor = {"record": 0, "anchor_hash": "", "observed_at": utc(datetime.now(UTC))}
            self.save("log:" + source, cursor)


def parse_xml(raw):
    root = ET.fromstring(raw)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("e:System", ns)

    def value(name):
        return system.findtext("e:" + name, namespaces=ns)

    provider = system.find("e:Provider", ns).get("Name", "unknown")
    observed = system.find("e:TimeCreated", ns).get("SystemTime")
    # datetime accepts Windows seven-digit fractional seconds, truncating to microseconds.
    observed_at = utc(datetime.fromisoformat(observed.replace("Z", "+00:00")))
    fields = {}
    for node in root.iter():
        local = node.tag.split("}")[-1]
        if local == "Data" and node.get("Name"):
            fields[node.get("Name")] = node.text or ""
        elif len(node) == 0 and local not in {"Data"} and root.find("e:UserData", ns) is not None:
            # Include 1102 UserData fields without dropping the original XML.
            fields[local] = node.text or ""
    level = int(value("Level") or 0)
    evidence = {
        "xml": raw,
        "provider": provider,
        "event_id": int(value("EventID")),
        "record_id": int(value("EventRecordID")),
        "computer": value("Computer"),
        "channel": value("Channel"),
        "fields": fields,
    }
    return (
        evidence,
        observed_at,
        evidence["record_id"],
        {1: "critical", 2: "high", 3: "medium"}.get(level, "info"),
    )
