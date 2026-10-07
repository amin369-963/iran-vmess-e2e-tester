# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, cast
from urllib.parse import urlparse

from vmess_db import get_db_path, get_top_reliable_configs, init_db, record_test_result
from vmess_pipeline import run_tests
from vmess_reports import (
    calculate_input_set_sha256, create_run_paths, generate_run_timestamp,
    sanitize_network_name, write_accepted_links, write_outputs,
)
from vmess_sources import DEFAULT_SOURCES, PROFILES, build_source_session, collect_links, read_text_file
from vmess_types import (
    APP_VERSION, SUPPORTED_PROTOCOLS, AppError, LinkResult, ProxyConfig, clean_text,
    link_protocol, parse_link,
)
from vmess_xray import (
    CREATION_FLAGS, build_balancer_xray_config, find_xray_executable, get_xray_version,
    stop_all_processes, test_config, wait_for_port,
)

DEFAULT_TEST_URLS = (
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
)
PROTOCOL_ALIASES = {"ss": "shadowsocks"}
PRINT_LOCK = threading.Lock()
ACCEPTED_SAVE_INTERVAL = 50


def log(message: str) -> None:
    with PRINT_LOCK:
        print(message, flush=True)


def validate_test_urls(urls: Iterable[str]) -> List[str]:
    valid: List[str] = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise AppError("test URLs must be valid HTTPS URLs")
        valid.append(url)
    if not valid:
        raise AppError("at least one test URL is required")
    return valid


def rank_key(link_result: LinkResult):
    latency = link_result.median_latency_ms if link_result.median_latency_ms is not None else float("inf")
    speed = getattr(link_result, "speed_kbps", 0.0)
    return (-link_result.score, -speed, latency, link_result.address)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Test VMess, VLESS, Trojan and Shadowsocks configurations "
                    "with deep quality checks, SQLite history, and automated Balancer proxy mode",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--profile", choices=sorted(PROFILES), default="default")
    parser.add_argument("--xray", default="", help="Path to xray.exe / xray (or its folder)")
    parser.add_argument("--protocol", action="append", default=[],
                        choices=sorted(set(SUPPORTED_PROTOCOLS) | set(PROTOCOL_ALIASES)),
                        help="Repeatable protocol filter; default tests all supported protocols")
    parser.add_argument("--seed-file", default="")
    parser.add_argument("--sources-file", default="")
    parser.add_argument("--source-url", action="append", default=[])
    parser.add_argument("--no-default-sources", action="store_true")
    parser.add_argument("--source-proxy", default="")
    parser.add_argument("--sample", type=int, default=0)
    parser.add_argument("--topk", type=int, default=0, help="Export only top K accepted configurations")
    parser.add_argument("--workers", type=int, default=0)
    parser.add_argument("--quality-workers", type=int, default=2,
                        help="Concurrent full tests of screening survivors")
    parser.add_argument("--single-stage", action="store_true",
                        help="Use the previous workflow without preliminary HTTPS screening")
    parser.add_argument("--attempts", type=int, default=0)
    parser.add_argument("--request-timeout", type=float, default=0.0)
    parser.add_argument("--startup-timeout", type=float, default=0.0)
    parser.add_argument("--no-tcp-precheck", action="store_true",
                        help="Skip the TCP reachability pre-filter before starting Xray")
    parser.add_argument("--tcp-timeout", type=float, default=3.0,
                        help="Connect timeout (seconds) for the TCP reachability pre-filter")
    parser.add_argument("--source-timeout", type=float, default=20.0)
    parser.add_argument("--min-score", type=int, default=-1)
    parser.add_argument("--test-url", action="append", default=[])
    parser.add_argument("--allow-insecure-server-cert", action="store_true")
    parser.add_argument("--network-name", default="unknown-network")
    parser.add_argument("--output-dir", default="results")
    parser.add_argument("--output-prefix", default="", help="Deprecated alias for --output-dir")
    parser.add_argument("--redact-links-in-report", action="store_true")
    parser.add_argument("--no-deep-test", action="store_true",
                        help="Skip deep testing (speed, cloudflare trace, and YouTube)")
    parser.add_argument("--verbose", action="store_true")

    # Connection / Balancer Proxy options
    parser.add_argument("--connect", action="store_true",
                        help="Start an active multi-config Xray Balancer proxy on localhost after testing")
    parser.add_argument("--use-db-top", action="store_true",
                        help="In --connect mode, immediately use top reliable configs from SQLite database")
    parser.add_argument("--balancer-size", type=int, default=5,
                        help="Number of best configurations to pool in the Balancer")
    parser.add_argument("--socks-port", type=int, default=10808,
                        help="Local SOCKS5 inbound port for the live Balancer proxy")
    parser.add_argument("--http-port", type=int, default=10809,
                        help="Local HTTP inbound port for the live Balancer proxy")
    return parser.parse_args()


def run_live_balancer(
    best_configs: List[ProxyConfig],
    xray_bin: Path,
    socks_port: int,
    http_port: int,
    allow_insecure: bool = False,
) -> None:
    """Run an isolated long-running Xray process with automated least-ping load balancing and observatory."""
    if not best_configs:
        log("[CONNECT] No working configuration available to start balancer.")
        return

    config_dict = build_balancer_xray_config(
        best_configs,
        socks_port=socks_port,
        http_port=http_port,
        allow_insecure_override=allow_insecure,
    )

    balancer_dir = Path("results") / "balancer_active"
    balancer_dir.mkdir(parents=True, exist_ok=True)
    config_file = balancer_dir / "balancer_config.json"
    config_file.write_text(json.dumps(config_dict, ensure_ascii=False, indent=2), encoding="utf-8")

    log("=" * 60)
    log("[CONNECT] Starting Live Multi-Config Balancer Proxy...")
    log(f"[CONNECT] Pooled {len(best_configs)} verified configs into automatic failover balancer.")
    log(f"[CONNECT] SOCKS5 Inbound: 127.0.0.1:{socks_port}")
    log(f"[CONNECT] HTTP Inbound:   127.0.0.1:{http_port}")
    log("[CONNECT] Health observatory: Every 15s using least-ping routing strategy.")
    log("[CONNECT] You can now configure your browser or system proxy to these ports.")
    log("[CONNECT] Press Ctrl+C to terminate proxy.")
    log("=" * 60)

    proc = subprocess.Popen(
        [str(xray_bin), "run", "-c", str(config_file)],
        creationflags=CREATION_FLAGS,
    )
    try:
        if wait_for_port(socks_port, proc, 8.0):
            log("[CONNECT] Proxy is UP and ready to accept connections!")
        while proc.poll() is None:
            time.sleep(1.0)
    except KeyboardInterrupt:
        log("\n[CONNECT] Stopping Balancer Proxy...")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        log("[CONNECT] Proxy stopped successfully.")


def main() -> int:
    args = parse_args()
    profile: Dict[str, Any] = dict(PROFILES[args.profile])
    network_name = clean_text(args.network_name)
    safe_network_name = sanitize_network_name(network_name)
    output_root = Path(args.output_prefix or args.output_dir).expanduser()
    db_path = get_db_path(output_root)
    init_db(db_path)

    xray = find_xray_executable(args.xray)
    xray_version = get_xray_version(xray)

    # Shortcut: Connect directly using historical database top performers
    if args.connect and args.use_db_top:
        top_db_items = get_top_reliable_configs(db_path, limit=args.balancer_size)
        if top_db_items:
            log(f"[DB] Retrieved {len(top_db_items)} top reliable configurations from SQLite database.")
            configs_to_balance: List[ProxyConfig] = []
            for db_record in top_db_items:
                try:
                    configs_to_balance.append(parse_link(str(db_record["link"])))
                except (AppError, ValueError, KeyError):
                    pass
            if configs_to_balance:
                run_live_balancer(
                    configs_to_balance,
                    xray,
                    args.socks_port,
                    args.http_port,
                    args.allow_insecure_server_cert,
                )
                return 0
        log("[DB] No enough historical configs found in DB. Falling back to fresh tests...")

    started_local = datetime.now().astimezone()
    started_utc = started_local.astimezone(timezone.utc)
    timestamp = generate_run_timestamp(started_local)
    run_paths = create_run_paths(output_root, network_name, timestamp)

    two_stage = not args.single_stage and not args.no_deep_test
    workers = args.workers or (8 if two_stage and args.profile == "default"
                              else int(str(profile["workers"])))
    attempts = args.attempts or int(str(profile["attempts"]))
    request_timeout = args.request_timeout or float(str(profile["request_timeout"]))
    startup_timeout = args.startup_timeout or float(str(profile["startup_timeout"]))
    retries = int(str(profile["source_retries"]))
    min_score = int(str(profile["min_score"])) if args.min_score < 0 else args.min_score
    offline_only = bool(profile["offline_only"])
    protocols = sorted({PROTOCOL_ALIASES.get(proto_item, proto_item) for proto_item in args.protocol}
                       or set(SUPPORTED_PROTOCOLS))

    if not 1 <= workers <= 16:
        raise AppError("workers must be between 1 and 16")
    if not 1 <= args.quality_workers <= 16:
        raise AppError("quality-workers must be between 1 and 16")
    if not 1 <= attempts <= 10:
        raise AppError("attempts must be between 1 and 10")
    if not 0 <= min_score <= 100:
        raise AppError("min-score must be between 0 and 100")
    if args.sample < 0 or args.topk < 0:
        raise AppError("sample and topk cannot be negative")
    try:
        import socks  # type: ignore  # noqa: F401
    except ImportError as e_socks:
        raise AppError('install SOCKS support with: python -m pip install "requests[socks]"') from e_socks

    urls = validate_test_urls(args.test_url or DEFAULT_TEST_URLS)

    sources: Set[str] = set()
    if not args.no_default_sources and not offline_only:
        sources.update(DEFAULT_SOURCES)
    if args.sources_file:
        for line in read_text_file(args.sources_file).splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                sources.add(line)
    sources.update(src.strip() for src in args.source_url if src.strip())
    if offline_only:
        sources.clear()
    if not sources and not args.seed_file:
        raise AppError("provide --seed-file or at least one source URL")

    session = build_source_session(args.source_proxy)
    try:
        collected = collect_links(sorted(sources), args.seed_file, session,
                                  retries, args.source_timeout, args.verbose, log)
    finally:
        session.close()
    raw_links = {link for link in collected if link_protocol(link) in protocols}
    input_hash = calculate_input_set_sha256(raw_links)

    parsed: Dict[str, ProxyConfig] = {}
    parse_failures: List[LinkResult] = []
    for link in sorted(raw_links):
        try:
            config = parse_link(link)
            parsed.setdefault(config.dedup_key, config)
        except AppError as e_parse:
            parse_failures.append(LinkResult(
                hashlib.sha256(link.encode("utf-8")).hexdigest(), link, "", 0,
                "", "", "", 0, 0.0, None, False, "parse", str(e_parse), [],
                protocol=link_protocol(link),
            ))
    configs = list(parsed.values())
    if args.sample and len(configs) > args.sample:
        random.SystemRandom().shuffle(configs)
        configs = configs[:args.sample]

    per_protocol: Dict[str, int] = {}
    for config in configs:
        per_protocol[config.protocol] = per_protocol.get(config.protocol, 0) + 1
    log("Proxy End-to-End Tester v%s | %s" % (APP_VERSION, xray_version))
    protocol_summary = ", ".join(f"{k}={v}" for k, v in sorted(per_protocol.items())) or "-"
    log(f"Network={network_name} Collected={len(raw_links)} Unique={len(parsed)} Testing={len(configs)} ({protocol_summary})")

    results: List[LinkResult] = []

    def save_result(config: ProxyConfig, result: LinkResult) -> None:
        # Screening survivors do not reach this callback until full testing ends.
        record_test_result(db_path, config, result, network_name)
        results.append(result)
        count = len(results)
        latency = "-" if result.median_latency_ms is None else f"{result.median_latency_ms:.0f}ms"
        speed_txt = f" speed={result.speed_kbps:.1f}KB/s" if result.speed_kbps > 0 else ""
        loc_txt = f" loc={result.country}" if result.country else ""
        log(f"[{count}/{len(configs)}] {'PASS' if result.accepted else 'FAIL'} {result.protocol} score={result.score} latency={latency}{speed_txt}{loc_txt}")
        if count % ACCEPTED_SAVE_INTERVAL == 0:
            accepted_so_far = sorted((item for item in results if item.accepted), key=rank_key)
            snapshot = accepted_so_far[:args.topk] if args.topk else accepted_so_far
            write_accepted_links(run_paths.accepted_txt, snapshot)
            log(f"Saved accepted links after {count} tested: {run_paths.accepted_txt}")

    full_test = partial(
        test_config, xray=xray, attempts=attempts, urls=urls,
        request_timeout=request_timeout, startup_timeout=startup_timeout,
        min_score=min_score, allow_insecure_override=args.allow_insecure_server_cert,
        verbose=args.verbose, logger=log, tcp_precheck=not args.no_tcp_precheck,
        tcp_timeout=args.tcp_timeout, deep_test=not args.no_deep_test,
    )
    screen_test = partial(
        test_config, xray=xray, attempts=1, urls=urls,
        request_timeout=request_timeout, startup_timeout=startup_timeout,
        min_score=0, allow_insecure_override=args.allow_insecure_server_cert,
        verbose=args.verbose, logger=log, tcp_precheck=not args.no_tcp_precheck,
        tcp_timeout=args.tcp_timeout, deep_test=False,
    )
    mode = "two-stage" if two_stage else "single-stage"
    log(f"Testing mode={mode} workers={workers}" +
        (f" quality-workers={args.quality_workers}" if two_stage else ""))
    interrupted, performance = run_tests(
        configs, screen_test if two_stage else full_test, save_result, workers,
        quality_test=full_test if two_stage else None,
        quality_workers=args.quality_workers, logger=log,
    )
    log("Testing time=%.1fs Throughput=%.1f configs/min Screening=%d Full=%d" % (
        performance["testing_elapsed_seconds"], performance["configs_per_minute"],
        performance["screening_completed"], performance["quality_completed"],
    ))

    accepted_all = sorted((accepted_cfg for accepted_cfg in results if accepted_cfg.accepted), key=rank_key)
    accepted_exported = accepted_all[:args.topk] if args.topk else accepted_all
    complete = sorted(parse_failures + results,
                      key=lambda res_item: (not res_item.accepted, -res_item.score, res_item.address, res_item.port))
    if args.seed_file and sources:
        source_mode = "seed+remote"
    elif args.seed_file:
        source_mode = "seed-only"
    else:
        source_mode = "remote-sources"
    metadata: Dict[str, object] = {
        "app_version": APP_VERSION,
        "run_timestamp": timestamp,
        "generated_at_local": started_local.strftime("%Y-%m-%d %H:%M:%S %z"),
        "generated_at_utc": started_utc.isoformat(),
        "network_name": network_name,
        "network_name_safe": safe_network_name,
        "profile": args.profile,
        "protocols": protocols,
        "python_version": platform.python_version(),
        "operating_system": f"{platform.system()} {platform.release()}".strip(),
        "xray_version": xray_version,
        "workers": workers, "attempts": attempts,
        "testing_mode": mode, "deep_test": not args.no_deep_test,
        "quality_workers": args.quality_workers if two_stage else workers,
        "screening_attempts": 1 if two_stage else 0,
        "performance": performance,
        "request_timeout": request_timeout, "startup_timeout": startup_timeout,
        "tcp_precheck": not args.no_tcp_precheck, "tcp_timeout": args.tcp_timeout,
        "min_score": min_score, "test_urls": urls,
        "source_mode": source_mode,
        "seed_file": Path(args.seed_file).name if args.seed_file else "-",
        "sample_requested": args.sample, "topk_requested": args.topk,
        "raw_links": len(raw_links), "unique_configs": len(parsed),
        "input_link_count": len(raw_links), "input_set_sha256": input_hash,
        "tested_count": len(results), "parse_failure_count": len(parse_failures),
        "not_tested_count": len(configs) - len(results),
        "interrupted": interrupted,
        "accepted_total": len(accepted_all), "accepted_exported": len(accepted_exported),
    }
    links_path, text_path, json_path, history_path = write_outputs(
        output_root, network_name, timestamp, accepted_exported, complete, metadata,
        args.redact_links_in_report, True,
    )
    log("Accepted=%d Exported=%d Tested=%d ParseFailures=%d%s" %
        (len(accepted_all), len(accepted_exported), len(results), len(parse_failures),
         " (INTERRUPTED)" if interrupted else ""))
    log(f"Accepted links: {links_path}")
    log(f"Text report: {text_path}")
    log(f"JSON report: {json_path}")
    log(f"History: {history_path}")
    log(f"SQLite DB: {db_path}")

    # Launch live balancer if requested
    if args.connect and accepted_exported:
        best_to_balance: List[ProxyConfig] = []
        for candidate in accepted_exported[:args.balancer_size]:
            try:
                best_to_balance.append(parse_link(candidate.link))
            except (AppError, ValueError):
                pass
        if best_to_balance:
            run_live_balancer(
                best_to_balance,
                xray,
                args.socks_port,
                args.http_port,
                args.allow_insecure_server_cert,
            )

    return 130 if interrupted else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        stop_all_processes()
        print("\n[STOPPED] Interrupted by user.", file=sys.stderr)
        raise SystemExit(130)
    except AppError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(2)
