# -*- coding: utf-8 -*-
"""Offline subscription-preview contract and tamper/expiry regression tests."""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from vmess_subscription import (
    BASE64_NAME, PLAIN_NAME, STATUS_NAME, build_private_preview,
    main, validate_private_preview,
)
from vmess_types import IDENTITY_VERSION, AppError, LinkResult, ProbeResult, parse_link

URL_A = "https://www.gstatic.com/generate_204"
URL_B = "https://cp.cloudflare.com/generate_204"
PROBE_PLAN = [URL_A, URL_B, URL_A, URL_B]
NOW = datetime(2026, 11, 16, 11, 0, tzinfo=timezone.utc)


def proxy_uri(i: int) -> str:
    return ("vless://00000000-0000-0000-0000-%012d@node%d.example:443"
            "?encryption=none&security=tls&sni=site.example&type=ws&path=/ws#private") % (i, i)


def verified_link(i: int) -> dict:
    config = parse_link(proxy_uri(i))
    result = LinkResult(
        key=config.dedup_key, link=config.raw, address=config.address,
        port=config.port, network=config.network,
        transport_security=config.transport_security,
        remark=config.remark, score=75, success_rate=1.0,
        median_latency_ms=150.0, accepted=True,
        protocol=config.protocol,
        probes=[
            ProbeResult(url=u, success=True, status_code=204,
                        elapsed_ms=150.0, bytes_read=0)
            for u in PROBE_PLAN
        ],
    )
    return result.to_dict()


def report_payload(count: int = 2) -> dict:
    accepted = [verified_link(i) for i in range(1, count + 1)]
    return {
        "metadata": {
            "identity_version": IDENTITY_VERSION,
            "network_name": "GitHub simulated, NOT ISP verified",
            "generated_at_utc": (NOW - timedelta(minutes=4)).isoformat(),
            "testing_completed_at_utc": (NOW - timedelta(minutes=3)).isoformat(),
            "interrupted": False,
            "not_tested_count": 0,
            "test_urls": [URL_A, URL_B],
            "attempts": 3,
            "sample_requested": 2,
            "tested_count": len(accepted),
            "accepted_total": len(accepted),
            "accepted_exported": len(accepted),
        },
        "tested_count": len(accepted),
        "accepted_count": len(accepted),
        "accepted": deepcopy(accepted),
        "all_results": deepcopy(accepted),
    }


class PrivatePreviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.report = self.directory / "private_report.json"
        self.output = self.directory / "results" / "preview"
        self.data = report_payload()
        self.save()

    def save(self):
        self.report.write_text(json.dumps(self.data), encoding="utf-8")

    def generate(self):
        return build_private_preview(self.report, self.output, now=NOW)

    def test_roundtrip_plain_base64_and_hashes(self):
        manifest = self.generate()
        self.assertEqual(manifest["exported_count"], 2)
        self.assertFalse(manifest["published"])
        self.assertFalse(manifest["redistribution_authorized"])
        self.assertFalse(manifest["vantage_verified"])
        self.assertEqual(manifest["distribution"], "private-local-preview")
        plain = (self.output / PLAIN_NAME).read_bytes()
        encoded = (self.output / BASE64_NAME).read_text("ascii")
        self.assertEqual(base64.b64decode(encoded), plain)
        self.assertEqual(plain.decode("utf-8").splitlines(),
                         [proxy_uri(1), proxy_uri(2)])
        self.assertEqual(validate_private_preview(self.output, now=NOW), manifest)
        status_text = (self.output / STATUS_NAME).read_text("utf-8")
        self.assertNotIn("node1.example", status_text)
        self.assertNotIn("000000000001", status_text)
        self.assertNotIn(str(self.report), status_text)
        self.assertIn('"files"', status_text)

    def test_tampered_content_rejected(self):
        self.generate()
        with (self.output / PLAIN_NAME).open("ab") as stream:
            stream.write(b"#unsafe")
        with self.assertRaisesRegex(AppError, "checksum"):
            validate_private_preview(self.output, now=NOW)

    def test_base64_parity_rejected_even_with_forged_hash(self):
        manifest = self.generate()
        mutated = (base64.b64encode(b"vless://malformed\n").decode("ascii") + "\n").encode("ascii")
        (self.output / BASE64_NAME).write_bytes(mutated)
        import hashlib
        manifest["files"][BASE64_NAME] = {
            "sha256": hashlib.sha256(mutated).hexdigest(), "bytes": len(mutated)
        }
        (self.output / STATUS_NAME).write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(AppError, "base64 subscription"):
            validate_private_preview(self.output, now=NOW)

    def test_expired_report_refused_without_creating_output(self):
        self.data["metadata"]["testing_completed_at_utc"] = (
            NOW - timedelta(days=2)).isoformat()
        self.data["metadata"]["generated_at_utc"] = (
            NOW - timedelta(days=2, minutes=1)).isoformat()
        self.save()
        with self.assertRaisesRegex(AppError, "stale"):
            self.generate()
        self.assertFalse(self.output.exists())

    def test_expired_preview_refused(self):
        self.generate()
        with self.assertRaisesRegex(AppError, "expired"):
            validate_private_preview(self.output, now=NOW + timedelta(hours=25))

    def test_interrupted_incomplete_or_legacy_report_rejected(self):
        for field, val in (
            ("interrupted", True),
            ("not_tested_count", 1),
            ("identity_version", 1),
        ):
            with self.subTest(field=field):
                self.data = report_payload()
                self.data["metadata"][field] = val
                self.save()
                with self.assertRaises(AppError):
                    self.generate()
                self.assertFalse(self.output.exists())

    def test_missing_or_future_completion_rejected(self):
        for value in (None, "2050-01-01T00:00:00Z", "2026-11-16T11:00:00"):
            with self.subTest(value=value):
                self.data = report_payload()
                self.data["metadata"]["testing_completed_at_utc"] = value
                self.save()
                with self.assertRaises(AppError):
                    self.generate()

    def test_mismatch_counts_or_accepted_provenance_rejected(self):
        changes = (
            ("counts", lambda p: p.update(accepted_count=1)),
            ("no tested source", lambda p: p["all_results"].pop()),
            ("mismatch identity", lambda p: p["accepted"][0].update(key="0" * 64)),
            ("one duplicate", lambda p: p["accepted"].append(deepcopy(p["accepted"][0]))),
            ("wrong accepted", lambda p: p["accepted"][0].update(accepted=False)),
        )
        for title, mutate in changes:
            with self.subTest(title=title):
                self.data = report_payload()
                mutate(self.data)
                self.save()
                with self.assertRaises(AppError):
                    self.generate()
                self.assertFalse(self.output.exists())

    def test_one_of_four_with_large_score_is_not_publishable(self):
        self.data["accepted"][0]["score"] = 100
        self.data["all_results"][0]["score"] = 100
        for idx in (1, 2, 3):
            for row in (self.data["accepted"][0], self.data["all_results"][0]):
                row["probes"][idx]["success"] = False
                row["probes"][idx]["status_code"] = 503
        self.save()
        with self.assertRaisesRegex(AppError, "sufficient HTTPS"):
            self.generate()

    def test_wrong_204_response_not_publishable(self):
        self.data["accepted"][0]["probes"][2]["status_code"] = 200
        self.data["accepted"][0]["probes"][3]["bytes_read"] = 5
        self.data["all_results"][0]["probes"][2]["status_code"] = 200
        self.data["all_results"][0]["probes"][3]["bytes_read"] = 5
        self.save()
        with self.assertRaisesRegex(AppError, "sufficient HTTPS"):
            self.generate()

    def test_existing_directory_is_never_overwritten(self):
        self.output.mkdir(parents=True)
        marker = self.output / "important.txt"
        marker.write_text("preserve", encoding="utf-8")
        with self.assertRaisesRegex(AppError, "already exists"):
            self.generate()
        self.assertEqual(marker.read_text("utf-8"), "preserve")

    def test_unexpected_file_or_symlink_is_refused(self):
        self.generate()
        (self.output / "private_report.json").write_text("should not be uploaded")
        with self.assertRaisesRegex(AppError, "exactly three"):
            validate_private_preview(self.output, now=NOW)

    def test_max_items_rejected_not_silently_truncated(self):
        with self.assertRaisesRegex(AppError, "max-items"):
            build_private_preview(self.report, self.output, max_items=1, now=NOW)
        self.assertFalse(self.output.exists())

    def test_command_line_build_and_validate_offline(self):
        self.data["metadata"]["generated_at_utc"] = (
            datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
        self.data["metadata"]["testing_completed_at_utc"] = (
            datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
        self.save()
        with patch("builtins.print"):
            self.assertEqual(main([
                "build", "--report", str(self.report),
                "--output-dir", str(self.output),
            ]), 0)
            self.assertEqual(main(["validate", "--directory", str(self.output)]), 0)


if __name__ == "__main__":
    unittest.main()
