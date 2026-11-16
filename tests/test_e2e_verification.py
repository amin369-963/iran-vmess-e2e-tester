# -*- coding: utf-8 -*-
"""Offline regression tests for the primary end-to-end verification gate."""
from dataclasses import replace
from pathlib import Path
from unittest import TestCase, mock

from vmess_types import ProbeResult, calculate_score, parse_link
from vmess_xray import (
    MAX_SPEED_TEST_BYTES,
    STOP_EVENT,
    _deep_quality_assessment,
    _primary_probes_verified,
    _run_probes,
    test_config,
)

URL_A = "https://www.gstatic.com/generate_204"
URL_B = "https://cp.cloudflare.com/generate_204"
PLAN = [URL_A, URL_B, URL_A, URL_B]


def probe(url, status=204, body=b"", elapsed=100.0):
    return ProbeResult(
        url=url,
        success=status == 204 and not body,
        status_code=status,
        elapsed_ms=elapsed,
        bytes_read=len(body),
        error="" if status == 204 and not body else "unexpected response",
    )


class DummyResponse:
    def __init__(self, status, body=b"", content=None, text=""):
        self.status_code = status
        self.content = body if content is None else content
        self.text = text
        self.raw = mock.Mock()
        self.raw.read.return_value = body
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.closed = True
        return False


class VerificationGateTests(TestCase):
    def setUp(self):
        STOP_EVENT.clear()

    def test_four_of_four_verified(self):
        self.assertTrue(_primary_probes_verified(
            [probe(url) for url in PLAN], PLAN))

    def test_three_of_four_with_both_endpoints_verified(self):
        observations = [probe(URL_A), probe(URL_B), probe(URL_A),
                        probe(URL_B, status=503)]
        self.assertTrue(_primary_probes_verified(observations, PLAN))

    def test_one_of_four_high_score_is_not_verified(self):
        observations = [
            probe(URL_A),
            probe(URL_B, status=503),
            probe(URL_A, status=503),
            probe(URL_B, status=503),
        ]
        score, rate, _ = calculate_score(
            observations, False, speed_kbps=3000, blocked_sites_passed=2)
        self.assertGreaterEqual(score, 60)
        self.assertEqual(rate, 0.25)
        self.assertFalse(_primary_probes_verified(observations, PLAN))
        result = self.run_test(observations, speed_kbps=3000, blocked=2)
        self.assertFalse(result.accepted)

    def test_one_endpoint_success_only_is_not_verified(self):
        observations = [probe(URL_A), probe(URL_B, status=503),
                        probe(URL_A), probe(URL_A)]
        self.assertFalse(_primary_probes_verified(observations, PLAN))

    def test_insufficient_or_incomplete_samples_are_not_verified(self):
        self.assertFalse(_primary_probes_verified(
            [probe(URL_A), probe(URL_B)], [URL_A, URL_B]))
        self.assertFalse(_primary_probes_verified(
            [probe(URL_A) for _ in range(4)], [URL_A] * 4))
        self.assertFalse(_primary_probes_verified(
            [probe(url) for url in PLAN[:3]], PLAN))

    def test_unexpected_code_or_body_cannot_be_primary_success(self):
        for status, body in ((200, b""), (302, b""), (204, b"wrong")):
            with self.subTest(status=status, body=body):
                session = mock.Mock()
                response = DummyResponse(status, body)
                session.get.return_value = response
                session.proxies = {}
                with mock.patch("vmess_xray.requests.Session",
                                return_value=session):
                    result = _run_probes(10808, [URL_A], 2.0)
                self.assertFalse(result[0].success)
                self.assertTrue(response.closed)
                self.assertFalse(session.trust_env)
                self.assertEqual(session.proxies["https"],
                                 "socks5h://127.0.0.1:10808")
                self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
                session.close.assert_called_once_with()

    def test_udp_mkcp_bypasses_tcp_precheck(self):
        cfg = replace(parse_link("trojan://pass@example.com:443#udp"),
                      network="mkcp")
        with mock.patch("vmess_xray.tcp_reachable",
                        side_effect=AssertionError("TCP precheck called")):
            result = self.run_test(
                [probe(url) for url in PLAN], config=cfg,
                tcp_precheck=True)
        self.assertTrue(result.accepted)

    def test_tcp_transport_keeps_tcp_precheck(self):
        cfg = parse_link("trojan://pass@example.com:443#tcp")
        with mock.patch("vmess_xray.tcp_reachable", return_value=False) as dial:
            result = self.run_test([probe(url) for url in PLAN],
                                   config=cfg, tcp_precheck=True)
        self.assertFalse(result.accepted)
        self.assertEqual(result.error_stage, "unreachable")
        dial.assert_called_once()

    def run_test(self, observations, config=None, speed_kbps=0.0,
                 blocked=0, tcp_precheck=False):
        cfg = config or parse_link("trojan://pass@example.com:443#test")
        outcome = ("", "", observations, False, speed_kbps, "", "", blocked)
        with mock.patch("vmess_xray._run_once", return_value=outcome), \
             mock.patch("vmess_xray.reserve_port", return_value=10808), \
             mock.patch("vmess_xray.release_port"):
            result = test_config(
                config=cfg, xray=Path("fake-xray"),
                attempts=3, urls=[URL_A, URL_B], request_timeout=2.0,
                startup_timeout=2.0, min_score=60,
                allow_insecure_override=False, verbose=False,
                tcp_precheck=tcp_precheck,
            )
        return result


class BoundedSpeedTests(TestCase):
    def setUp(self):
        STOP_EVENT.clear()

    def test_speed_download_stops_at_512_kib(self):
        emitted = []

        def endless_chunks():
            while True:
                emitted.append(1)
                yield b"x" * 16384

        trace = DummyResponse(200, text="ip=192.0.2.10\\nloc=US")
        video = DummyResponse(204)
        speed = DummyResponse(200)
        speed.iter_content = mock.Mock(return_value=endless_chunks())
        session = mock.Mock()
        session.proxies = {}
        session.get.side_effect = [trace, video, speed]
        with mock.patch("vmess_xray.requests.Session", return_value=session):
            throughput, country, ip, blocked = _deep_quality_assessment(
                port=10808, request_timeout=2.0)
        self.assertGreater(throughput, 0.0)
        self.assertEqual(country, "US")
        self.assertEqual(ip, "192.0.2.10")
        self.assertEqual(blocked, 1)
        self.assertEqual(len(emitted), MAX_SPEED_TEST_BYTES // 16384)
        self.assertTrue(all(resp.closed for resp in (trace, video, speed)))
        session.close.assert_called_once_with()
