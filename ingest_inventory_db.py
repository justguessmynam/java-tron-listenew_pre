#!/usr/bin/env python3
"""Import sampled TRX INV observations from gzip archives into local SQLite."""

import gzip
import ipaddress
import os
import re
import socket
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


BASE_DIR = Path(os.environ.get("TRON_BASE_DIR", "/root/java-tron-listenew_pre"))
LOG_DIR = BASE_DIR / "logs/inventory"
DB_PATH = BASE_DIR / "logs/inventory_extracted/inventory_observations.sqlite"
TIME_ZONE = ZoneInfo("Asia/Shanghai")
BATCH_SIZE = 5000

SAMPLE_SEGMENTS = (
    ("A01", "2026-11-16 22:08:00", "2026-11-16 22:13:00"),
    ("A02", "2026-11-16 22:33:00", "2026-11-16 22:37:00"),
    ("B01", "2026-11-17 02:05:00", "2026-11-17 02:10:00"),
    ("B02", "2026-11-17 02:30:00", "2026-11-17 02:35:00"),
    ("B03", "2026-11-17 02:55:00", "2026-11-17 03:00:00"),
    ("B04", "2026-11-17 03:00:00", "2026-11-17 03:05:00"),
    ("B05", "2026-11-17 03:10:00", "2026-11-17 03:15:00"),
    ("B06", "2026-11-17 03:45:00", "2026-11-17 03:50:00"),
    ("B07", "2026-11-17 03:55:00", "2026-11-17 04:00:00"),
    ("B08", "2026-11-17 04:50:00", "2026-11-17 04:55:00"),
)

RECORD_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) "
    r"INV remote=(\S+) active=(true|false) type=(\S+) "
    r"latencyMs=(-?\d+) batchSize=(\d+) hash=([0-9a-fA-F]{64})(?=\s|$)"
)


def parse_segments():
    segments = []
    for segment_id, start_text, end_text in SAMPLE_SEGMENTS:
        start = datetime.strptime(start_text, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=TIME_ZONE
        )
        end = datetime.strptime(end_text, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=TIME_ZONE
        )
        if start >= end:
            raise ValueError(f"Invalid sample interval: {segment_id}")
        segments.append((segment_id, start, end))
    return segments


def detect_observer_ip():
    configured = os.environ.get("TRON_OBSERVER_IP", "").strip()
    if configured:
        return str(ipaddress.ip_address(configured))

    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("1.1.1.1", 80))
        address = probe.getsockname()[0]
    finally:
        probe.close()

    parsed = ipaddress.ip_address(address)
    if parsed.is_unspecified or parsed.is_loopback:
        raise RuntimeError(
            "Could not determine this VPS IP; set TRON_OBSERVER_IP explicitly"
        )
    return str(parsed)


def get_birth_epoch(path):
    result = subprocess.run(
        ["stat", "-c", "%W", "--", str(path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    birth_epoch = int(result.stdout.strip())
    if birth_epoch <= 0:
        raise RuntimeError(f"Filesystem does not report birth time for {path}")
    return birth_epoch


def find_selected_archives(segments):
    if not LOG_DIR.is_dir():
        raise FileNotFoundError(f"Inventory log directory not found: {LOG_DIR}")

    selected = []
    for path in sorted(LOG_DIR.iterdir()):
        if not path.is_file() or path.suffix.lower() != ".gz":
            continue

        birth_epoch = get_birth_epoch(path)
        birth_time = datetime.fromtimestamp(birth_epoch, TIME_ZONE)
        for segment_id, start, end in segments:
            if start <= birth_time < end:
                stat_result = path.stat()
                selected.append(
                    {
                        "path": path,
                        "birth_epoch": birth_epoch,
                        "segment_id": segment_id,
                        "size_bytes": stat_result.st_size,
                        "mtime_ns": stat_result.st_mtime_ns,
                    }
                )
                break
    return selected


def initialize_database(connection, observer_ip):
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    connection.execute("PRAGMA busy_timeout = 30000")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS database_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS source_archives (
            archive_id INTEGER PRIMARY KEY,
            path TEXT NOT NULL UNIQUE,
            birth_epoch INTEGER NOT NULL,
            segment_id TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            imported_at TEXT NOT NULL,
            observation_count INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS inv_observations (
            observation_id INTEGER PRIMARY KEY,
            observer_id TEXT NOT NULL,
            tx_hash TEXT NOT NULL,
            log_time TEXT NOT NULL,
            remote TEXT NOT NULL,
            latency_ms INTEGER NOT NULL,
            batch_size INTEGER NOT NULL,
            active INTEGER NOT NULL CHECK (active IN (0, 1)),
            archive_id INTEGER NOT NULL,
            FOREIGN KEY (archive_id)
                REFERENCES source_archives (archive_id)
                ON DELETE CASCADE
        );
        """
    )
    existing = connection.execute(
        "SELECT value FROM database_metadata WHERE key = 'observer_id'"
    ).fetchone()
    if existing and existing[0] != observer_ip:
        raise ValueError(
            f"Database belongs to observer {existing[0]}, not {observer_ip}"
        )
    connection.execute(
        "INSERT OR REPLACE INTO database_metadata (key, value) VALUES (?, ?)",
        ("observer_id", observer_ip),
    )
    connection.commit()


def import_archive(connection, archive, observer_ip):
    path_text = str(archive["path"].resolve())
    metadata = (
        archive["birth_epoch"],
        archive["segment_id"],
        archive["size_bytes"],
        archive["mtime_ns"],
    )
    previous = connection.execute(
        """SELECT archive_id, birth_epoch, segment_id, size_bytes, mtime_ns
           FROM source_archives WHERE path = ?""",
        (path_text,),
    ).fetchone()
    if previous and tuple(previous[1:]) == metadata:
        return "unchanged", 0

    connection.execute("BEGIN IMMEDIATE")
    try:
        if previous:
            connection.execute(
                "DELETE FROM source_archives WHERE archive_id = ?",
                (previous[0],),
            )

        cursor = connection.execute(
            """INSERT INTO source_archives
               (path, birth_epoch, segment_id, size_bytes, mtime_ns,
                imported_at, observation_count)
               VALUES (?, ?, ?, ?, ?, ?, 0)""",
            (
                path_text,
                archive["birth_epoch"],
                archive["segment_id"],
                archive["size_bytes"],
                archive["mtime_ns"],
                datetime.now(TIME_ZONE).isoformat(timespec="seconds"),
            ),
        )
        archive_id = cursor.lastrowid
        insert_rows = []
        total = 0

        with gzip.open(
            archive["path"], "rt", encoding="utf-8", errors="strict"
        ) as source:
            for line in source:
                match = RECORD_RE.match(line)
                if not match:
                    continue
                log_time, remote, active, inv_type, latency, batch_size, tx_hash = (
                    match.groups()
                )
                if inv_type != "TRX":
                    continue

                datetime.strptime(log_time, "%Y-%m-%d %H:%M:%S.%f")
                remote = remote.removeprefix("/")
                insert_rows.append(
                    (
                        observer_ip,
                        tx_hash.lower(),
                        log_time,
                        remote,
                        int(latency),
                        int(batch_size),
                        int(active == "true"),
                        archive_id,
                    )
                )
                if len(insert_rows) >= BATCH_SIZE:
                    connection.executemany(
                        """INSERT INTO inv_observations
                           (observer_id, tx_hash, log_time, remote, latency_ms,
                            batch_size, active, archive_id)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        insert_rows,
                    )
                    total += len(insert_rows)
                    insert_rows.clear()

        if insert_rows:
            connection.executemany(
                """INSERT INTO inv_observations
                   (observer_id, tx_hash, log_time, remote, latency_ms,
                    batch_size, active, archive_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                insert_rows,
            )
            total += len(insert_rows)

        connection.execute(
            "UPDATE source_archives SET observation_count = ? WHERE archive_id = ?",
            (total, archive_id),
        )
        connection.commit()
        return "imported", total
    except Exception:
        connection.rollback()
        raise


def main():
    segments = parse_segments()
    observer_ip = detect_observer_ip()
    archives = find_selected_archives(segments)
    if not archives:
        raise RuntimeError("No gzip files have birth times in the selected intervals")

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=30)
    imported_files = 0
    skipped_files = 0
    observation_count = 0
    failures = []

    try:
        initialize_database(connection, observer_ip)
        for archive in archives:
            print(
                f"[{archive['segment_id']}] {archive['path'].name} "
                f"birth={datetime.fromtimestamp(archive['birth_epoch'], TIME_ZONE)}",
                flush=True,
            )
            try:
                status, count = import_archive(connection, archive, observer_ip)
                if status == "unchanged":
                    skipped_files += 1
                    print("  unchanged; already imported", flush=True)
                else:
                    imported_files += 1
                    observation_count += count
                    print(f"  imported TRX observations: {count}", flush=True)
            except Exception as error:
                failures.append((archive["path"].name, str(error)))
                print(f"  ERROR: {error}", file=sys.stderr, flush=True)

        connection.execute(
            """CREATE INDEX IF NOT EXISTS idx_inv_tx_time
               ON inv_observations (tx_hash, log_time)"""
        )
        connection.commit()

        totals = connection.execute(
            """SELECT COUNT(*), COUNT(DISTINCT tx_hash)
               FROM inv_observations"""
        ).fetchone()
        print(f"Observer IP: {observer_ip}")
        print(f"Selected gzip files: {len(archives)}")
        print(f"Imported files: {imported_files}; unchanged files: {skipped_files}")
        print(f"New observations: {observation_count}")
        print(f"Database observations: {totals[0]}; distinct transactions: {totals[1]}")
        print(f"Database: {DB_PATH}")
        print(f"Failed files: {len(failures)}")
        if failures:
            return 1
        return 0
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"Import failed: {error}", file=sys.stderr)
        sys.exit(1)
