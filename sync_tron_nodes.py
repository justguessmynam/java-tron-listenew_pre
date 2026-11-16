#!/usr/bin/env python3

import ipaddress
import os
import re
import shutil
import stat
import sys
from datetime import datetime
from pathlib import Path

import pymysql


DB_HOST = "23.94.175.185"
DB_PORT = 3306
DB_NAME = "tron_db"
DB_USER = "root"
DB_PASSWORD = "Wcf@123123"
DB_TABLE = "public_online_nodes_test"

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "framework/src/main/resources/config.conf"

QUERY = f"""
SELECT DISTINCT
    TRIM(ipv4),
    tcpPort
FROM {DB_TABLE}
WHERE ipv4 IS NOT NULL
  AND TRIM(ipv4) <> ''
  AND tcpPort BETWEEN 1 AND 65535
ORDER BY TRIM(ipv4), tcpPort
"""


def query_nodes():
    connection = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        connect_timeout=15,
        read_timeout=120,
        write_timeout=30,
        autocommit=True,
    )

    try:
        with connection.cursor() as cursor:
            cursor.execute(QUERY)
            rows = cursor.fetchall()
    finally:
        connection.close()

    nodes = set()
    invalid_count = 0

    for raw_ip, raw_port in rows:
        try:
            address = ipaddress.IPv4Address(str(raw_ip).strip())
            port = int(raw_port)
        except (ipaddress.AddressValueError, ValueError, TypeError):
            invalid_count += 1
            continue

        if not 1 <= port <= 65535:
            invalid_count += 1
            continue

        nodes.add((int(address), str(address), port))

    if not nodes:
        raise RuntimeError(
            "Database returned no valid IPv4 TCP endpoints; "
            "keep the existing active/passive lists"
        )

    if invalid_count:
        print(f"Ignored invalid database endpoints: {invalid_count}")

    return sorted(nodes)


def detect_newline(raw_content):
    if raw_content.count(b"\r\n") > raw_content.count(b"\n") // 2:
        return "\r\n"
    return "\n"


def build_node_block(name, nodes, newline):
    lines = [f"  {name} = ["]
    total = len(nodes)

    for index, (_, address, port) in enumerate(nodes):
        comma = "," if index < total - 1 else ""
        lines.append(f'    "{address}:{port}"{comma}')

    lines.append("  ]")
    return newline.join(lines)


def replace_node_block(config_text, name, node_block):
    pattern = re.compile(
        rf"(?ms)^  {re.escape(name)}\s*=\s*\[.*?^  \][ \t]*(?=\r?$)"
    )

    updated_text, replacement_count = pattern.subn(
        lambda _: node_block,
        config_text,
        count=1,
    )

    if replacement_count != 1:
        raise RuntimeError(
            f"Cannot uniquely locate node.{name} in {CONFIG_FILE}"
        )

    return updated_text


def atomic_write(raw_content):
    temporary_file = CONFIG_FILE.with_name(
        CONFIG_FILE.name + ".node-sync.tmp"
    )
    backup_file = CONFIG_FILE.with_name(
        CONFIG_FILE.name + ".node-sync.bak"
    )

    current_mode = stat.S_IMODE(CONFIG_FILE.stat().st_mode)

    with temporary_file.open("wb") as file:
        file.write(raw_content)
        file.flush()
        os.fsync(file.fileno())

    os.chmod(temporary_file, current_mode)
    shutil.copy2(CONFIG_FILE, backup_file)
    os.replace(temporary_file, CONFIG_FILE)


def main():
    if not CONFIG_FILE.is_file():
        raise FileNotFoundError(
            f"java-tron config does not exist: {CONFIG_FILE}"
        )

    nodes = query_nodes()

    old_raw_content = CONFIG_FILE.read_bytes()
    newline = detect_newline(old_raw_content)
    old_content = old_raw_content.decode("utf-8")

    active_block = build_node_block("active", nodes, newline)
    passive_block = build_node_block("passive", nodes, newline)

    new_content = replace_node_block(
        old_content,
        "active",
        active_block,
    )
    new_content = replace_node_block(
        new_content,
        "passive",
        passive_block,
    )

    new_raw_content = new_content.encode("utf-8")

    if new_raw_content == old_raw_content:
        print(
            f"{datetime.now().isoformat(timespec='seconds')} "
            f"active/passive nodes unchanged, total={len(nodes)}"
        )
        return

    atomic_write(new_raw_content)

    print(
        f"{datetime.now().isoformat(timespec='seconds')} "
        f"updated active/passive nodes, total={len(nodes)}, "
        f"config={CONFIG_FILE}"
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(
            f"{datetime.now().isoformat(timespec='seconds')} "
            f"sync failed: {error}",
            file=sys.stderr,
        )
        sys.exit(1)
