# -*- coding: utf-8 -*-
"""Deterministic, offline verification of opt-in feed collection and source yield."""
import base64
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import main
from vmess_db import get_top_reliable_configs, init_db, record_test_result
from vmess_sources import (
    MAX_SOURCE_BYTES, PILOT_SOURCES, collect_links, fetch_source, validate_source_url,
)
from vmess_types import IDENTITY_VERSION, AppError, LinkResult, parse_link


def uri(number, remark=""):
    return (
        "vless://00000000-0000-0000-0000-%012d@server%d.example:443"
        "?security=tls&sni=site.example&type=ws&path=%%2F#%s"
    ) % (number, number, remark)


class FakeResponse:
    def __init__(self, status=200, content=b""):
        self.status_code = status
        self.payload = content
        self.encoding = "utf-8"
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.closed = True

    def iter_content(self, chunk_size):
        for i in range(0, len(self.payload), chunk_size):
            yield self.payload[i:i + chunk_size]


class FetchSafetyTests(unittest.TestCase):
    def test_private_and_unsafe_source_urls_are_rejected(self):
        for url in (
            "http://example.com/feed", "https://localhost/configs",
            "https://127.0.0.1/secret", "https://[::1]/configs",
            "https://192.168.0.1/sub", "https://169.254.169.254/latest",
            "https://user:secret@example.com/feed",
            "https://example.com:8080/feed", "https://example.com/feed#fragment",
            "https://metadata.google.internal/computeMetadata/v1",
        ):
            with self.subTest(url=url):
                with self.assertRaises(AppError):
                    validate_source_url(url)
        validate_source_url(PILOT_SOURCES["reference-verified"]["url"])

    def test_redirect_and_oversize_fail_closed(self):
        session = Mock()
        session.get.return_value = FakeResponse(302)
        with self.assertRaisesRegex(AppError, "HTTP 302"):
            fetch_source("https://example.com/sub", session, 0, 2.0, False)
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
        session.get.return_value = FakeResponse(200, b"x" * 11)
        with self.assertRaisesRegex(AppError, "byte limit"):
            fetch_source("https://example.com/sub", session, 0, 2.0, False, max_bytes=10)

    def test_run_wide_budget_counts_partial_failed_download(self):
        session = Mock()
        session.get.return_value = FakeResponse(200, b"x" * 11)
        remaining = [8]
        with self.assertRaisesRegex(AppError, "byte budget"):
            fetch_source("https://example.com/sub", session, 0, 2.0, False,
                         max_bytes=20, remaining_budget=remaining)
        self.assertEqual(remaining[0], 0)

    def test_no_github_token_on_raw_feed(self):
        session = Mock()
        session.get.return_value = FakeResponse(200, uri(1).encode())
        with patch("vmess_sources.GITHUB_TOKEN", "private-token"):
            text = fetch_source(PILOT_SOURCES["multi-fetcher"]["url"],
                                session, 0, 2.0, False)
        self.assertIn("vless://", text)
        self.assertNotIn("Authorization", session.get.call_args.kwargs["headers"])

    def test_failed_source_is_distinguished_from_empty_or_invalid(self):
        a = "https://example.com/a"
        b = "https://example.com/b"
        c = "https://example.com/c"
        sources = [a, b, c]
        health = {}
        responses = {a: uri(1), b: "", c: "<html>login</html>"}
        with patch("vmess_sources.fetch_source",
                   side_effect=lambda url, *args: responses[url]):
            found = collect_links(sources, "", None, 0, 2.0, False,
                                  logger=lambda msg: None, source_health=health)
        self.assertEqual(found, {uri(1)})
        self.assertEqual([health[url]["status"] for url in sources],
                         ["ok", "empty", "invalid"])
        self.assertTrue(health[a]["fetched_at_utc"])

    def test_pilot_capped_by_distinct_connection_identity(self):
        url = PILOT_SOURCES["reference-verified"]["url"]
        first = "\n".join([uri(1, "first"), uri(1, "renamed"), uri(2), uri(3)])
        health = {}
        with patch("vmess_sources.PILOT_UNIQUE_LIMIT", 2), \
             patch("vmess_sources.fetch_source", return_value=first):
            found1 = collect_links([url], "", None, 0, 2.0, False,
                                   logger=lambda msg: None, source_health=health)
        with patch("vmess_sources.PILOT_UNIQUE_LIMIT", 2), \
             patch("vmess_sources.fetch_source", return_value="\n".join(reversed(first.splitlines()))):
            found2 = collect_links([url], "", None, 0, 2.0, False,
                                   logger=lambda msg: None)
        self.assertEqual({parse_link(x).dedup_key for x in found1},
                         {parse_link(x).dedup_key for x in found2})
        self.assertEqual(len(found1), 2)
        self.assertEqual(health[url]["raw_candidates"], 4)
        self.assertEqual(health[url]["status"], "capped")

    def test_exhausted_budget_skips_later_feed_without_network_request(self):
        a = "https://example.com/a"
        b = "https://example.com/b"
        health = {}
        with patch("vmess_sources.fetch_source", return_value="x" * 10) as fetcher:
            collect_links([a, b], "", None, 0, 2.0, False,
                          logger=lambda msg: None, total_budget_bytes=10,
                          source_health=health)
        self.assertEqual(fetcher.call_count, 1)
        self.assertEqual(health[a]["status"], "invalid")
        self.assertEqual(health[b]["status"], "budget_skipped")


class IdentityVersionTests(unittest.TestCase):
    def test_connection_fields_change_identity_but_display_remark_does_not(self):
        base = (
            "vless://00000000-0000-0000-0000-000000000001@server.example:443"
            "?encryption=none&security=tls&sni=site.example&type=ws&path=%2F"
            "&alpn=h2&fp=chrome&allowInsecure=false#one"
        )
        assert IDENTITY_VERSION >= 2
        reference = parse_link(base)
        self.assertEqual(reference.dedup_key, parse_link(base.replace("#one", "#two")).dedup_key)
        variants = (
            base.replace("alpn=h2", "alpn=http%2F1.1"),
            base.replace("fp=chrome", "fp=firefox"),
            base.replace("allowInsecure=false", "allowInsecure=true"),
            base.replace("type=ws", "type=ws&headerType=http"),
        )
        for value in variants:
            with self.subTest(uri=value):
                self.assertNotEqual(reference.dedup_key, parse_link(value).dedup_key)

    def test_legacy_sqlite_schema_is_migrated_without_data_loss(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "legacy.sqlite"
            with sqlite3.connect(str(db)) as conn:
                conn.execute("""
                    CREATE TABLE configs (
                        dedup_key TEXT PRIMARY KEY, link TEXT NOT NULL,
                        protocol TEXT NOT NULL, address TEXT NOT NULL,
                        port INTEGER NOT NULL, network TEXT, security TEXT,
                        remark TEXT, first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL, total_tests INTEGER DEFAULT 0,
                        success_tests INTEGER DEFAULT 0, last_score INTEGER DEFAULT 0,
                        last_speed_kbps REAL DEFAULT 0, last_latency REAL,
                        last_country TEXT DEFAULT ''
                    )
                """)
                conn.execute("""
                    INSERT INTO configs (dedup_key, link, protocol, address,
                                         port, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, ("legacy-identity", uri(1), "vless", "server1.example",
                      443, "2026-01-01", "2026-01-01"))
            init_db(db)
            with sqlite3.connect(str(db)) as conn:
                self.assertEqual(
                    conn.execute("SELECT identity_version FROM configs WHERE dedup_key=?",
                                 ("legacy-identity",)).fetchone()[0], 1)
                self.assertEqual(conn.execute("SELECT count(*) FROM configs").fetchone()[0], 1)

    def test_old_sqlite_records_do_not_reenter_rankings(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "history.sqlite"
            init_db(db)
            config = parse_link(uri(1))
            accepted = LinkResult(
                config.dedup_key, config.raw, config.address, config.port,
                config.network, config.transport_security, config.remark,
                90, 1.0, 100.0, True, protocol=config.protocol,
            )
            record_test_result(db, config, accepted, "Test")
            self.assertEqual(len(get_top_reliable_configs(db)), 1)
            with sqlite3.connect(str(db)) as conn:
                conn.execute("UPDATE configs SET identity_version=1")
            self.assertEqual(get_top_reliable_configs(db), [])


class PilotMainTests(unittest.TestCase):
    def test_pilot_incremental_and_exclusive_accepted_are_distinct(self):
        default = "https://example.com/baseline"
        pilot = PILOT_SOURCES["reference-verified"]["url"]
        feeds = {default: "\n".join([uri(1), uri(2)]),
                 pilot: "\n".join([uri(1, "renamed"), uri(3)])}
        with tempfile.TemporaryDirectory() as directory:
            args = [
                "main.py", "--output-dir", directory, "--network-name", "Test",
                "--single-stage", "--workers", "1", "--no-deep-test",
                "--sample-seed", "123", "--pilot-source", "reference-verified",
            ]

            def fake_test(config, **kwargs):
                return LinkResult(
                    config.dedup_key, config.raw, config.address, config.port,
                    config.network, config.transport_security, config.remark,
                    90, 1.0, 100.0, True, protocol=config.protocol,
                )

            with patch("sys.argv", args), patch("main.DEFAULT_SOURCES", [default]), \
                 patch("vmess_sources.fetch_source", side_effect=lambda url, *x: feeds[url]), \
                 patch("main.find_xray_executable", return_value=Path("fake-xray")), \
                 patch("main.get_xray_version", return_value="Xray test"), \
                 patch("main.test_config", side_effect=fake_test), \
                 patch("main.log"):
                self.assertEqual(main.main(), 0)

            reports = list(Path(directory).rglob("*_report.json"))
            self.assertEqual(len(reports), 1)
            metadata = json.loads(reports[0].read_text(encoding="utf-8"))["metadata"]
            rows = metadata["source_priority"]
            pilot_row = next(row for row in rows if row["fetch"].get("pilot_id"))
            baseline_row = next(row for row in rows if not row["fetch"].get("pilot_id"))
            self.assertEqual(pilot_row["accepted"], 2)
            self.assertEqual(pilot_row["accepted_exclusive"], 1)
            self.assertEqual(pilot_row["pilot_incremental_accepted"], 1)
            self.assertEqual(baseline_row["accepted_exclusive"], 1)
            self.assertEqual(metadata["identity_version"], 2)
            self.assertEqual(metadata["pilot_sources_requested"], ["reference-verified"])


if __name__ == "__main__":
    unittest.main()
