# -*- coding: utf-8 -*-
import base64
import json
import tempfile
import unittest
from pathlib import Path

import main
import vmess_sources
from vmess_db import get_top_reliable_configs, init_db, record_test_result
from vmess_types import (
    AppError,
    LinkResult,
    ProbeResult,
    calculate_score,
    extract_links_from_subscription,
    parse_link,
)
from vmess_xray import build_balancer_xray_config


class SourceSessionTests(unittest.TestCase):
    def test_source_session_ignores_ambient_requests_environment(self):
        session = vmess_sources.build_source_session("")
        try:
            self.assertFalse(session.trust_env)
            self.assertEqual(session.proxies, {})
        finally:
            session.close()

    def test_explicit_source_proxy_is_still_supported(self):
        proxy = "socks5h://127.0.0.1:1080"
        session = vmess_sources.build_source_session(proxy)
        try:
            self.assertFalse(session.trust_env)
            self.assertEqual(session.proxies["http"], proxy)
            self.assertEqual(session.proxies["https"], proxy)
        finally:
            session.close()

    def test_raw_github_feeds_do_not_receive_github_token(self):
        self.assertFalse(vmess_sources.should_attach_github_token("raw.githubusercontent.com"))
        self.assertTrue(vmess_sources.should_attach_github_token("api.github.com"))

    def test_default_sources_contain_public_feeds(self):
        self.assertTrue(len(vmess_sources.DEFAULT_SOURCES) >= 4)
        self.assertTrue(all(url.startswith("https://raw.githubusercontent.com/")
                            for url in vmess_sources.DEFAULT_SOURCES))


class TestProxyParser(unittest.TestCase):
    def test_parse_vmess(self):
        vm_dict = {
            "v": "2",
            "ps": "test_vmess",
            "add": "example.com",
            "port": 443,
            "id": "a3482e88-686a-4a58-8126-99c9df64b7bf",
            "aid": "0",
            "net": "ws",
            "type": "none",
            "host": "example.com",
            "path": "/ws",
            "tls": "tls",
        }
        raw = "vmess://" + base64.b64encode(json.dumps(vm_dict).encode()).decode()
        cfg = parse_link(raw)
        self.assertEqual(cfg.protocol, "vmess")
        self.assertEqual(cfg.address, "example.com")
        self.assertEqual(cfg.port, 443)
        self.assertEqual(cfg.transport_security, "tls")

    def test_parse_vless_reality(self):
        link = (
            "vless://a3482e88-686a-4a58-8126-99c9df64b7bf@example.com:443"
            "?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome"
            "&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2"
            "&type=tcp&flow=xtls-rprx-vision#reality_node"
        )
        cfg = parse_link(link)
        self.assertEqual(cfg.protocol, "vless")
        self.assertEqual(cfg.transport_security, "reality")
        self.assertEqual(cfg.public_key, "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc")
        self.assertEqual(cfg.remark, "reality_node")

    def test_parse_trojan(self):
        link = "trojan://password123@example.com:443?security=tls&sni=example.com&type=ws&path=/tr#trojan_node"
        cfg = parse_link(link)
        self.assertEqual(cfg.protocol, "trojan")
        self.assertEqual(cfg.password, "password123")
        self.assertEqual(cfg.network, "websocket")

    def test_parse_shadowsocks(self):
        link = "ss://" + base64.urlsafe_b64encode(b"aes-256-gcm:pass123").decode().rstrip("=") + "@example.com:8388#ss_node"
        cfg = parse_link(link)
        self.assertEqual(cfg.protocol, "shadowsocks")
        self.assertEqual(cfg.method, "aes-256-gcm")
        self.assertEqual(cfg.password, "pass123")

    def test_invalid_scheme(self):
        with self.assertRaises(AppError):
            parse_link("unknown://test")

    def test_subscription_extraction(self):
        content = "vmess://dummy\nvless://dummy2\n"
        encoded = base64.b64encode(content.encode()).decode()
        links = extract_links_from_subscription(encoded)
        self.assertTrue(len(links) >= 2)


class TestScoring(unittest.TestCase):
    def test_scoring_weights(self):
        probes = [
            ProbeResult(url="https://test", success=True, status_code=200, elapsed_ms=150.0, bytes_read=100),
            ProbeResult(url="https://test", success=True, status_code=200, elapsed_ms=160.0, bytes_read=100),
        ]
        score, rate, median = calculate_score(probes, insecure_tls=False, speed_kbps=1200.0, blocked_sites_passed=1)
        self.assertEqual(rate, 1.0)
        self.assertIsNotNone(median)
        self.assertGreater(score, 60)


class TestDatabaseAndBalancer(unittest.TestCase):
    def test_db_operations(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test.db"
            init_db(db_path)
            link = "trojan://pass@example.com:443#test"
            cfg = parse_link(link)
            res = LinkResult(
                key=cfg.dedup_key,
                link=cfg.raw,
                address=cfg.address,
                port=cfg.port,
                network=cfg.network,
                transport_security=cfg.transport_security,
                remark=cfg.remark,
                score=85,
                success_rate=1.0,
                median_latency_ms=200.0,
                accepted=True,
                protocol=cfg.protocol,
                speed_kbps=500.0,
                country="US",
            )
            record_test_result(db_path, cfg, res, "TestNet")
            top = get_top_reliable_configs(db_path, limit=5)
            self.assertEqual(len(top), 1)
            self.assertEqual(top[0]["last_score"], 85)

    def test_balancer_config_builder(self):
        cfg = parse_link("trojan://pass@example.com:443#test")
        balancer_cfg = build_balancer_xray_config([cfg], socks_port=10808, http_port=10809)
        self.assertIn("routing", balancer_cfg)
        self.assertIn("observatory", balancer_cfg)
        self.assertIn("balancers", balancer_cfg["routing"])


if __name__ == "__main__":
    unittest.main()
