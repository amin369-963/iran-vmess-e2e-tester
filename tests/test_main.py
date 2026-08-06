import base64
import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

import main


def make_link(payload):
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return "vmess://" + encoded


def make_result(*, accepted=True, score=90, stage="", error="", link=None):
    return main.LinkResult(
        key="k" + str(score) + stage,
        link=link or make_link({
            "add": "example.com",
            "port": 443,
            "id": "11111111-1111-1111-1111-111111111111",
            "net": "ws",
            "tls": "tls",
        }),
        address="example.com",
        port=443,
        network="websocket",
        transport_security="tls",
        remark="sample",
        score=score,
        success_rate=1.0 if accepted else 0.0,
        median_latency_ms=320.0 if accepted else None,
        accepted=accepted,
        error_stage=stage,
        error=error,
        probes=[],
    )


def metadata(network_name="MCI Tehran"):
    return {
        "network_name": network_name,
        "profile": "mci",
        "generated_at_local": "2026-08-06 12:42:00 +0330",
        "generated_at_utc": "2026-08-06T09:12:00+00:00",
        "python_version": "3.9.14",
        "xray_version": "Xray 25.1.1",
        "operating_system": "Windows 10",
        "test_urls": ["https://example.com/generate_204"],
        "workers": 2,
        "attempts": 3,
        "request_timeout": 20.0,
        "startup_timeout": 12.0,
        "min_score": 55,
        "source_mode": "seed-only",
        "seed_file": "configs.txt",
        "sample_requested": 0,
        "raw_links": 2,
        "unique_configs": 2,
        "input_link_count": 2,
        "input_set_sha256": "abc123",
    }


class VmessParserTests(unittest.TestCase):
    def test_parses_websocket_tls(self):
        cfg = main.parse_vmess_link(make_link({
            "v": "2",
            "ps": "sample",
            "add": "example.com",
            "port": "443",
            "id": "11111111-1111-1111-1111-111111111111",
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": "cdn.example.com",
            "path": "/ws",
            "tls": "tls",
            "sni": "edge.example.com",
        }))
        self.assertEqual(cfg.address, "example.com")
        self.assertEqual(cfg.port, 443)
        self.assertEqual(cfg.network, "websocket")
        self.assertEqual(cfg.sni, "edge.example.com")
        self.assertEqual(cfg.path, "/ws")

    def test_rejects_invalid_port(self):
        with self.assertRaises(main.AppError):
            main.parse_vmess_link(make_link({
                "add": "example.com",
                "port": "70000",
                "id": "id",
            }))

    def test_extracts_base64_subscription(self):
        link = make_link({"add": "example.com", "port": 443, "id": "id"})
        subscription = base64.b64encode((link + "\n").encode()).decode()
        self.assertEqual(main.extract_links_from_subscription(subscription), [link])


class ScoreTests(unittest.TestCase):
    def test_perfect_fast_score(self):
        probes = [
            main.ProbeResult("https://example.com", True, 204, 200.0, 0),
            main.ProbeResult("https://example.com", True, 204, 300.0, 0),
            main.ProbeResult("https://example.com", True, 204, 400.0, 0),
        ]
        score, rate, median = main.calculate_score(probes, insecure_tls=False)
        self.assertEqual(score, 100)
        self.assertEqual(rate, 1.0)
        self.assertEqual(median, 300.0)

    def test_insecure_tls_penalty(self):
        probes = [main.ProbeResult("https://example.com", True, 204, 300.0, 0)]
        secure, _, _ = main.calculate_score(probes, insecure_tls=False)
        insecure, _, _ = main.calculate_score(probes, insecure_tls=True)
        self.assertEqual(secure - insecure, 10)


class OutputTests(unittest.TestCase):
    def test_sanitizes_network_name(self):
        self.assertEqual(main.sanitize_network_name(" MCI Tehran / Home! "), "MCI_Tehran_Home")
        self.assertEqual(main.sanitize_network_name("ایرانسل تهران"), "ایرانسل_تهران")

    def test_rejects_empty_or_invalid_network_name(self):
        for value in ("", "   ", "///***"):
            with self.subTest(value=value), self.assertRaises(main.AppError):
                main.sanitize_network_name(value)

    def test_timestamp_paths_are_different(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            first = main.create_run_paths(Path(temp_dir), "MCI", "20260806_120000")
            second = main.create_run_paths(Path(temp_dir), "MCI", "20260806_120001")
            self.assertNotEqual(first.report_txt, second.report_txt)

    def test_refuses_to_overwrite_existing_run(self):
        accepted = [make_result()]
        with tempfile.TemporaryDirectory() as temp_dir:
            args = (Path(temp_dir), "MCI", "20260806_120000", accepted, accepted, metadata())
            main.write_outputs(*args)
            with self.assertRaises(main.AppError):
                main.write_outputs(*args)

    def test_report_is_utf8_sig_and_csv_is_not_created(self):
        accepted = [make_result()]
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = main.write_outputs(
                Path(temp_dir), "MCI", "20260806_120000", accepted, accepted, metadata()
            )
            report_txt = paths[1]
            self.assertTrue(report_txt.read_bytes().startswith(b"\xef\xbb\xbf"))
            self.assertEqual(list(Path(temp_dir).rglob("*.csv")), [])

    def test_input_hash_is_order_independent(self):
        first = main.calculate_input_set_sha256(["b", "a", "a"])
        second = main.calculate_input_set_sha256(["a", "b"])
        self.assertEqual(first, second)

    def test_text_report_has_required_sections(self):
        report = main.render_text_report(
            [make_result()],
            [make_result(), make_result(accepted=False, score=0, stage="request", error="timeout")],
            metadata(),
            False,
        )
        for heading in (
            "Run information",
            "Summary",
            "Failure stages",
            "Accepted configurations",
            "Rejected configurations",
            "Input set SHA-256",
        ):
            self.assertIn(heading, report)

    def test_redacts_links_in_report_only(self):
        result = make_result()
        report = main.render_text_report([result], [result], metadata(), True)
        self.assertIn("Link: [REDACTED]", report)
        self.assertNotIn(result.link, report)

    def test_history_appends_multiple_runs(self):
        accepted = [make_result()]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            main.write_outputs(root, "MCI", "20260806_120000", accepted, accepted, metadata("MCI"))
            main.write_outputs(root, "Irancell", "20260806_120100", accepted, accepted, metadata("Irancell"))
            history = (root / "test_history.txt").read_text(encoding="utf-8-sig")
            self.assertEqual(len([line for line in history.splitlines() if line.strip()]), 2)
            self.assertIn("MCI", history)
            self.assertIn("Irancell", history)

    def test_timestamp_format(self):
        value = main.generate_run_timestamp(datetime(2026, 8, 6, 12, 42, 5))
        self.assertEqual(value, "20260806_124205")


if __name__ == "__main__":
    unittest.main()
