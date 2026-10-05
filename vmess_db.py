# -*- coding: utf-8 -*-
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DB_LOCK = threading.Lock()


def get_db_path(root_dir: Path) -> Path:
    return root_dir / "proxy_history.db"


def init_db(db_path: Path) -> None:
    with DB_LOCK:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    network_name TEXT NOT NULL,
                    input_hash TEXT,
                    tested_count INTEGER,
                    accepted_count INTEGER,
                    median_latency REAL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS configs (
                    dedup_key TEXT PRIMARY KEY,
                    link TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    address TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    network TEXT,
                    security TEXT,
                    remark TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    total_tests INTEGER DEFAULT 0,
                    success_tests INTEGER DEFAULT 0,
                    last_score INTEGER DEFAULT 0,
                    last_speed_kbps REAL DEFAULT 0,
                    last_latency REAL,
                    last_country TEXT DEFAULT ''
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dedup_key TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    network_name TEXT NOT NULL,
                    accepted INTEGER NOT NULL,
                    score INTEGER NOT NULL,
                    latency_ms REAL,
                    speed_kbps REAL,
                    error_stage TEXT,
                    error_msg TEXT,
                    country TEXT,
                    ip TEXT,
                    FOREIGN KEY(dedup_key) REFERENCES configs(dedup_key)
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sources (
                    url TEXT PRIMARY KEY,
                    total_fetched INTEGER DEFAULT 0,
                    total_valid INTEGER DEFAULT 0,
                    total_accepted INTEGER DEFAULT 0,
                    last_fetched TEXT
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_records_key ON test_records(dedup_key)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_records_time ON test_records(timestamp)")
            conn.commit()


def record_test_result(
    db_path: Path,
    config,  # ProxyConfig
    result,  # LinkResult
    network_name: str,
    timestamp: Optional[str] = None,
) -> None:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    with DB_LOCK:
        with sqlite3.connect(str(db_path)) as conn:
            cur = conn.cursor()
            # Upsert into configs
            cur.execute("""
                INSERT INTO configs (
                    dedup_key, link, protocol, address, port, network, security, remark,
                    first_seen, last_seen, total_tests, success_tests, last_score,
                    last_speed_kbps, last_latency, last_country
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                ON CONFLICT(dedup_key) DO UPDATE SET
                    link = excluded.link,
                    last_seen = excluded.last_seen,
                    total_tests = total_tests + 1,
                    success_tests = success_tests + excluded.success_tests,
                    last_score = excluded.last_score,
                    last_speed_kbps = excluded.last_speed_kbps,
                    last_latency = excluded.last_latency,
                    last_country = CASE WHEN excluded.last_country != '' THEN excluded.last_country ELSE last_country END
            """, (
                config.dedup_key,
                config.raw,
                config.protocol,
                config.address,
                config.port,
                config.network,
                config.transport_security,
                config.remark,
                timestamp,
                timestamp,
                1 if result.accepted else 0,
                result.score,
                getattr(result, "speed_kbps", 0.0),
                result.median_latency_ms,
                getattr(result, "country", "") or "",
            ))

            # Insert test record
            cur.execute("""
                INSERT INTO test_records (
                    dedup_key, timestamp, network_name, accepted, score, latency_ms,
                    speed_kbps, error_stage, error_msg, country, ip
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                config.dedup_key,
                timestamp,
                network_name,
                1 if result.accepted else 0,
                result.score,
                result.median_latency_ms,
                getattr(result, "speed_kbps", 0.0),
                result.error_stage,
                result.error[:300] if result.error else "",
                getattr(result, "country", "") or "",
                getattr(result, "ip", "") or "",
            ))
            conn.commit()


def get_config_uptime(db_path: Path, dedup_key: str) -> Tuple[int, int, float]:
    """Returns (total_tests, success_tests, uptime_percentage)."""
    with DB_LOCK:
        with sqlite3.connect(str(db_path)) as conn:
            cur = conn.cursor()
            cur.execute("SELECT total_tests, success_tests FROM configs WHERE dedup_key = ?", (dedup_key,))
            row = cur.fetchone()
            if not row or row[0] == 0:
                return (0, 0, 0.0)
            return (row[0], row[1], (row[1] / row[0]) * 100.0)


def get_top_reliable_configs(db_path: Path, limit: int = 10, min_tests: int = 1) -> List[Dict[str, object]]:
    with DB_LOCK:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("""
                SELECT dedup_key, link, protocol, address, port, network, security, remark,
                       total_tests, success_tests,
                       ROUND((CAST(success_tests AS REAL) / total_tests) * 100, 1) as uptime,
                       last_score, last_speed_kbps, last_latency, last_country
                FROM configs
                WHERE total_tests >= ? AND success_tests > 0
                ORDER BY uptime DESC, last_score DESC, last_speed_kbps DESC, last_latency ASC
                LIMIT ?
            """, (min_tests, limit))
            return [dict(row) for row in cur.fetchall()]


def record_source_stats(
    db_path: Path,
    source_url: str,
    fetched: int,
    valid: int,
    accepted: int
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with DB_LOCK:
        with sqlite3.connect(str(db_path)) as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO sources (url, total_fetched, total_valid, total_accepted, last_fetched)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    total_fetched = total_fetched + excluded.total_fetched,
                    total_valid = total_valid + excluded.total_valid,
                    total_accepted = total_accepted + excluded.total_accepted,
                    last_fetched = excluded.last_fetched
            """, (source_url, fetched, valid, accepted, now))
            conn.commit()
