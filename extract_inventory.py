#!/usr/bin/env python3
"""Extract target transaction INV records from local gzip archives."""

import csv
import gzip
import re
import shutil
import sys
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path


BASE_DIR = Path("/root/java-tron-listenew_pre")
CSV_FILE = BASE_DIR / "Transactions_63.csv"
LOG_DIR = BASE_DIR / "logs/inventory"
OUTPUT_DIR = BASE_DIR / "logs/inventory_extracted"

HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
ARCHIVE_RE = re.compile(r"inventory-(\d{4}-\d{2}-\d{2})\.(\d+)\.log\.gz\Z")
RECORD_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) "
    r"INV remote=(\S+) active=(true|false) type=(\S+) "
    r"latencyMs=(\S+) batchSize=(\d+) hash=([0-9a-fA-F]{64})(?=\s|$)"
)


def read_target_hashes():
    targets = set()
    with CSV_FILE.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or "Txn Hash" not in reader.fieldnames:
            raise ValueError("CSV must contain a 'Txn Hash' column")
        for row_number, row in enumerate(reader, start=2):
            tx_hash = (row.get("Txn Hash") or "").strip().lower()
            if not HASH_RE.fullmatch(tx_hash):
                raise ValueError(f"Invalid transaction hash at CSV row {row_number}")
            targets.add(tx_hash)

    if not targets:
        raise ValueError("CSV contains no target transaction hashes")

    prefixes = {}
    for tx_hash in targets:
        prefix = tx_hash[:8]
        if prefix in prefixes and prefixes[prefix] != tx_hash:
            raise ValueError(f"Transaction filename prefix collision: {prefix}")
        prefixes[prefix] = tx_hash
    return targets


def ordered_archives():
    if not LOG_DIR.is_dir():
        raise FileNotFoundError(f"Inventory directory not found: {LOG_DIR}")

    archives = []
    for path in LOG_DIR.iterdir():
        if not path.is_file() or path.suffix != ".gz":
            continue
        match = ARCHIVE_RE.fullmatch(path.name)
        if not match:
            raise ValueError(f"Cannot determine chronological order for {path.name}")
        archives.append((match.group(1), int(match.group(2)), path))

    if not archives:
        raise FileNotFoundError(f"No .gz files found in {LOG_DIR}")
    archives.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in archives]


def prepare_staging(staging):
    if not OUTPUT_DIR.exists():
        return
    if OUTPUT_DIR.is_symlink() or not OUTPUT_DIR.is_dir():
        raise ValueError(f"Output path is not a regular directory: {OUTPUT_DIR}")

    shutil.copytree(OUTPUT_DIR, staging, dirs_exist_ok=True, symlinks=True)
    old_summary = staging / "summary.csv"
    if not old_summary.is_file():
        return

    with old_summary.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        required = {"tx_hash", "file_name"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError("Existing summary.csv has an unexpected format")
        for row in reader:
            tx_hash = (row.get("tx_hash") or "").strip().lower()
            filename = (row.get("file_name") or "").strip()
            if not filename:
                continue
            if not HASH_RE.fullmatch(tx_hash) or filename != f"{tx_hash[:8]}.txt":
                raise ValueError("Existing summary.csv contains an unsafe filename")
            (staging / filename).unlink(missing_ok=True)


def publish_results(staging):
    backup = None
    if OUTPUT_DIR.exists():
        backup = Path(tempfile.mkdtemp(
            prefix=".inventory-extracted-backup-", dir=OUTPUT_DIR.parent
        ))
        backup.rmdir()
        OUTPUT_DIR.rename(backup)

    try:
        staging.rename(OUTPUT_DIR)
    except Exception:
        if backup is not None:
            backup.rename(OUTPUT_DIR)
        raise

    if backup is not None:
        shutil.rmtree(backup)


def extract():
    targets = read_target_hashes()
    archives = ordered_archives()
    OUTPUT_DIR.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(
        prefix=".inventory-extracted-", dir=OUTPUT_DIR.parent
    ))
    handles = {}
    counts = Counter()
    last_times = {}
    time_regressions = 0
    failed_archives = []

    try:
        prepare_staging(staging)
        try:
            for archive in archives:
                print(f"Scanning {archive.name} ...", flush=True)
                try:
                    with gzip.open(
                        archive, "rt", encoding="utf-8", errors="strict"
                    ) as source:
                        for line in source:
                            match = RECORD_RE.match(line)
                            if not match:
                                continue

                            timestamp, remote, active, inv_type, latency, batch_size, tx_hash = (
                                match.groups()
                            )
                            tx_hash = tx_hash.lower()
                            if inv_type != "TRX" or tx_hash not in targets:
                                continue

                            datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
                            if tx_hash in last_times and timestamp < last_times[tx_hash]:
                                time_regressions += 1
                            last_times[tx_hash] = timestamp

                            if tx_hash not in handles:
                                output = staging / f"{tx_hash[:8]}.txt"
                                if output.exists() or output.is_symlink():
                                    raise FileExistsError(
                                        f"Output file is not tracked by the previous summary: {output.name}"
                                    )
                                handles[tx_hash] = output.open(
                                    "w", encoding="utf-8", newline="\n"
                                )

                            peer = remote.removeprefix("/")
                            handles[tx_hash].write(
                                f"{timestamp} {peer} {latency} {batch_size} {active}\n"
                            )
                            counts[tx_hash] += 1
                except (OSError, EOFError, UnicodeError, ValueError) as error:
                    failed_archives.append((archive.name, str(error)))
                    print(f"ERROR {archive.name}: {error}", file=sys.stderr, flush=True)
        finally:
            for handle in handles.values():
                handle.close()

        if failed_archives:
            raise RuntimeError(
                f"{len(failed_archives)} gzip file(s) failed; existing results were preserved"
            )

        with (staging / "summary.csv").open(
            "w", encoding="utf-8", newline=""
        ) as output:
            writer = csv.writer(output)
            writer.writerow(["tx_hash", "file_name", "matched_lines"])
            for tx_hash in sorted(targets):
                filename = f"{tx_hash[:8]}.txt" if counts[tx_hash] else ""
                writer.writerow([tx_hash, filename, counts[tx_hash]])

        publish_results(staging)
        print(f"Targets: {len(targets)}; gzip files: {len(archives)}")
        print(f"Matched transactions: {len(counts)}; matched lines: {sum(counts.values())}")
        print(f"Timestamp regressions: {time_regressions}; failed files: 0")
        print(f"Output: {OUTPUT_DIR}")
    finally:
        if staging.exists():
            shutil.rmtree(staging)


if __name__ == "__main__":
    try:
        extract()
    except Exception as error:
        print(f"Extraction failed: {error}", file=sys.stderr)
        sys.exit(1)
