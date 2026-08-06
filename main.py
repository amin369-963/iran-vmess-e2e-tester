# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import platform
import random
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Set
from urllib.parse import urlparse

from vmess_reports import (
    calculate_input_set_sha256, create_run_paths, generate_run_timestamp,
    render_text_report, sanitize_network_name, write_outputs,
)
from vmess_sources import DEFAULT_SOURCES, PROFILES, build_source_session, collect_links, read_text_file
from vmess_types import (
    AppError, LinkResult, ProbeResult, VmessConfig, calculate_score, clean_text,
    extract_links_from_subscription, extract_vmess_links, parse_vmess_link,
)
from vmess_xray import find_xray_executable, get_xray_version, test_config

APP_VERSION = "3.1.0"
DEFAULT_TEST_URLS = (
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
)
PRINT_LOCK = threading.Lock()


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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Test VMess configurations through isolated Xray processes",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--profile", choices=sorted(PROFILES), default="default")
    parser.add_argument("--xray", default="", help="Path to xray.exe or xray")
    parser.add_argument("--seed-file", default="")
    parser.add_argument("--sources-file", default="")
    parser.add_argument("--source-url", action="append", default=[])
    parser.add_argument("--no-default-sources", action="store_true")
    parser.add_argument("--source-proxy", default="")
    parser.add_argument("--sample", type=int, default=0)
    parser.add_argument("--topk", type=int, default=0)
    parser.add_argument("--workers", type=int, default=0)
    parser.add_argument("--attempts", type=int, default=0)
    parser.add_argument("--request-timeout", type=float, default=0.0)
    parser.add_argument("--startup-timeout", type=float, default=0.0)
    parser.add_argument("--source-timeout", type=float, default=20.0)
    parser.add_argument("--min-score", type=int, default=-1)
    parser.add_argument("--test-url", action="append", default=[])
    parser.add_argument("--allow-insecure-server-cert", action="store_true")
    parser.add_argument("--network-name", default="unknown-network")
    parser.add_argument("--output-dir", default="results")
    parser.add_argument("--output-prefix", default="", help="Deprecated alias for --output-dir")
    parser.add_argument("--redact-links-in-report", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    profile = dict(PROFILES[args.profile])
    network_name = clean_text(args.network_name)
    safe_network_name = sanitize_network_name(network_name)
    output_root = Path(args.output_prefix or args.output_dir).expanduser()
    started_local = datetime.now().astimezone()
    started_utc = started_local.astimezone(timezone.utc)
    timestamp = generate_run_timestamp(started_local)

    workers = args.workers or int(profile["workers"])
    attempts = args.attempts or int(profile["attempts"])
    request_timeout = args.request_timeout or float(profile["request_timeout"])
    startup_timeout = args.startup_timeout or float(profile["startup_timeout"])
    retries = int(profile["source_retries"])
    min_score = int(profile["min_score"]) if args.min_score < 0 else args.min_score
    offline_only = bool(profile["offline_only"])

    if not 1 <= workers <= 16:
        raise AppError("workers must be between 1 and 16")
    if not 1 <= attempts <= 10:
        raise AppError("attempts must be between 1 and 10")
    if not 0 <= min_score <= 100:
        raise AppError("min-score must be between 0 and 100")
    if args.sample < 0 or args.topk < 0:
        raise AppError("sample and topk cannot be negative")
    try:
        import socks  # type: ignore  # noqa: F401
    except ImportError as exc:
        raise AppError('install SOCKS support with: python -m pip install "requests[socks]"') from exc

    xray = find_xray_executable(args.xray)
    xray_version = get_xray_version(xray)
    urls = validate_test_urls(args.test_url or DEFAULT_TEST_URLS)

    sources: Set[str] = set()
    if not args.no_default_sources and not offline_only:
        sources.update(DEFAULT_SOURCES)
    if args.sources_file:
        for line in read_text_file(args.sources_file).splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                sources.add(line)
    sources.update(item.strip() for item in args.source_url if item.strip())
    if offline_only:
        sources.clear()
    if not sources and not args.seed_file:
        raise AppError("provide --seed-file or at least one source URL")

    session = build_source_session(args.source_proxy)
    try:
        raw_links = collect_links(sorted(sources), args.seed_file, session,
                                  retries, args.source_timeout, args.verbose, log)
    finally:
        session.close()
    input_hash = calculate_input_set_sha256(raw_links)

    parsed: Dict[str, VmessConfig] = {}
    parse_failures: List[LinkResult] = []
    for link in sorted(raw_links):
        try:
            config = parse_vmess_link(link)
            parsed.setdefault(config.dedup_key, config)
        except AppError as exc:
            parse_failures.append(LinkResult(
                hashlib.sha256(link.encode("utf-8")).hexdigest(), link, "", 0,
                "", "", "", 0, 0.0, None, False, "parse", str(exc), []
            ))
    configs = list(parsed.values())
    if args.sample and len(configs) > args.sample:
        random.SystemRandom().shuffle(configs)
        configs = configs[:args.sample]

    log("VMess End-to-End Tester v%s | %s" % (APP_VERSION, xray_version))
    log("Network=%s Collected=%d Unique=%d Testing=%d" %
        (network_name, len(raw_links), len(parsed), len(configs)))
    results: List[LinkResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(test_config, config, xray, attempts, urls,
                            request_timeout, startup_timeout, min_score,
                            args.allow_insecure_server_cert, args.verbose, log): config
            for config in configs
        }
        for count, future in enumerate(concurrent.futures.as_completed(future_map), 1):
            config = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                result = LinkResult(config.dedup_key, config.raw, config.address,
                                    config.port, config.network, config.transport_security,
                                    config.remark, 0, 0.0, None, False, "worker",
                                    "%s: %s" % (type(exc).__name__, exc), [])
            results.append(result)
            latency = "-" if result.median_latency_ms is None else "%.0fms" % result.median_latency_ms
            log("[%d/%d] %s score=%d latency=%s" %
                (count, len(configs), "PASS" if result.accepted else "FAIL",
                 result.score, latency))

    accepted_all = sorted((item for item in results if item.accepted),
                          key=lambda item: (-item.score,
                                            item.median_latency_ms if item.median_latency_ms is not None else float("inf"),
                                            item.address))
    accepted_exported = accepted_all[:args.topk] if args.topk else accepted_all
    complete = sorted(parse_failures + results,
                      key=lambda item: (not item.accepted, -item.score, item.address, item.port))
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
        "python_version": platform.python_version(),
        "operating_system": f"{platform.system()} {platform.release()}".strip(),
        "xray_version": xray_version,
        "workers": workers, "attempts": attempts,
        "request_timeout": request_timeout, "startup_timeout": startup_timeout,
        "min_score": min_score, "test_urls": urls,
        "source_mode": source_mode,
        "seed_file": Path(args.seed_file).name if args.seed_file else "-",
        "sample_requested": args.sample, "topk_requested": args.topk,
        "raw_links": len(raw_links), "unique_configs": len(parsed),
        "input_link_count": len(raw_links), "input_set_sha256": input_hash,
        "tested_count": len(results), "parse_failure_count": len(parse_failures),
        "accepted_total": len(accepted_all), "accepted_exported": len(accepted_exported),
    }
    links_path, text_path, json_path, history_path = write_outputs(
        output_root, network_name, timestamp, accepted_exported, complete, metadata,
        args.redact_links_in_report,
    )
    log("Accepted=%d Exported=%d Tested=%d ParseFailures=%d" %
        (len(accepted_all), len(accepted_exported), len(results), len(parse_failures)))
    log("Accepted links: %s" % links_path)
    log("Text report: %s" % text_path)
    log("JSON report: %s" % json_path)
    log("History: %s" % history_path)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[STOPPED] Interrupted by user.", file=sys.stderr)
        raise SystemExit(130)
    except AppError as exc:
        print("[ERROR] %s" % exc, file=sys.stderr)
        raise SystemExit(2)
