import base64
import json
import unittest

import main


def make_link(payload):
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return "vmess://" + encoded


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


if __name__ == "__main__":
    unittest.main()
