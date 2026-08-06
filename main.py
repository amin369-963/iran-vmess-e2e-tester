# -*- coding: utf-8 -*-
"""Iran VMess End-to-End Tester.

Collects VMess links, runs each candidate through an isolated Xray Core
process, and measures real HTTPS traffic through a local SOCKS5 tunnel.
Compatible with Python 3.9+.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import csv
import hashlib
import json
import os
import random
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote, urlparse

import requests


APP_VERSION = "3.0.0"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
XRAY_PATH_ENV = os.getenv("XRAY_PATH", "").strip()
MAX_SOURCE_BYTES = 12 * 1024 * 1024
VMESS_RE = re.compile(r"vmess://[^\s\"'<>]+", re.IGNORECASE)
PRINT_LOCK = threading.Lock()

DEFAULT_TEST_URLS = (
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
)

DEFAULT_SOURCES = (
    "https://raw.githubusercontent.com/Mohammadgb0078/IRV2ray/main/vmess.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vmess",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vmess",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/main/v2ray",
)

PROFILES: Dict[str, Dict[str, object]] = {
    "default": dict(description="Balanced end-to-end test", workers=4, attempts=3,
                    request_timeout=12.0, startup_timeout=7.0, source_retries=2,
                    min_score=60, offline_only=False),
    "mci": dict(description="Conservative settings for MCI/mobile access", workers=3,
                attempts=3, request_timeout=18.0, startup_timeout=9.0,
                source_retries=3, min_score=55, offline_only=False),
    "irancell": dict(description="Conservative settings for Irancell/mobile access",
                     workers=3, attempts=3, request_timeout=18.0,
                     startup_timeout=9.0, source_retries=3, min_score=55,
                     offline_only=False),
    "tci": dict(description="Balanced settings for fixed TCI access", workers=5,
                attempts=3, request_timeout=14.0, startup_timeout=8.0,
                source_retries=2, min_score=60, offline_only=False),
    "fast": dict(description="Fast screening with one probe", workers=6, attempts=1,
                 request_timeout=9.0, startup_timeout=6.0, source_retries=1,
                 min_score=45, offline_only=False),
    "national": dict(description="Offline-only mode for restricted connectivity",
                     workers=2, attempts=2, request_timeout=20.0,
                     startup_timeout=10.0, source_retries=0, min_score=45,
                     offline_only=True),
}


class AppError(RuntimeError):
    """Expected user-facing error."""


@dataclass(frozen=True)
class VmessConfig:
    raw: str
    address: str
    port: int
    user_id: str
    alter_id: int
    cipher: str
    network: str
    transport_security: str
    sni: str
    host: str
    path: str
    service_name: str
    authority: str
    alpn: Tuple[str, ...]
    fingerprint: str
    allow_insecure: bool
    remark: str
    header_type: str

    @property
    def dedup_key(self) -> str:
        values = (
            self.address.lower(), str(self.port), self.user_id, str(self.alter_id),
            self.cipher, self.network, self.transport_security, self.sni.lower(),
            self.host.lower(), self.path, self.service_name, self.authority.lower(),
        )
        return hashlib.sha256("|".join(values).encode("utf-8")).hexdigest()


@dataclass
class ProbeResult:
    url: str
    success: bool
    status_code: Optional[int]
    elapsed_ms: Optional[float]
    bytes_read: int
    error: str = ""


@dataclass
class LinkResult:
    key: str
    link: str
    address: str
    port: int
    network: str
    transport_security: str
    remark: str
    score: int
    success_rate: float
    median_latency_ms: Optional[float]
    accepted: bool
    error_stage: str = ""
    error: str = ""
    probes: List[ProbeResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def log(message: str) -> None:
    with PRINT_LOCK:
        print(message, flush=True)


def clean_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return clean_text(value[0]) if value else ""
    return str(value).strip()


def parse_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return clean_text(value).lower() in {"1", "true", "yes", "on"}


def parse_port(value: object) -> Optional[int]:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def decode_base64_text(value: str) -> str:
    compact = "".join(value.strip().split())
    if not compact:
        return ""
    padded = compact + "=" * ((4 - len(compact) % 4) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(padded.encode("ascii")).decode("utf-8", errors="strict")
        except Exception:
            pass
    return ""


def extract_vmess_links(text: str) -> List[str]:
    found: List[str] = []
    seen: Set[str] = set()
    for match in VMESS_RE.finditer(text or ""):
        link = match.group(0).rstrip(")]}>،,;؛。.'\"")
        if link not in seen:
            seen.add(link)
            found.append(link)
    return found


def extract_links_from_subscription(text: str) -> List[str]:
    links = extract_vmess_links(text)
    decoded = decode_base64_text(text)
    if decoded and decoded != text:
        seen = set(links)
        for link in extract_vmess_links(decoded):
            if link not in seen:
                seen.add(link)
                links.append(link)
    return links


def normalize_network(value: str) -> str:
    mapping = {
        "": "raw", "tcp": "raw", "raw": "raw",
        "ws": "websocket", "websocket": "websocket",
        "grpc": "grpc", "kcp": "mkcp", "mkcp": "mkcp",
        "httpupgrade": "httpupgrade", "http-upgrade": "httpupgrade",
        "xhttp": "xhttp", "splithttp": "xhttp",
    }
    key = value.strip().lower()
    if key not in mapping:
        raise AppError("unsupported transport: %s" % (key or "<empty>"))
    return mapping[key]


def parse_alpn(value: object) -> Tuple[str, ...]:
    if isinstance(value, list):
        raw_items = [clean_text(item) for item in value]
    else:
        raw = clean_text(value)
        raw_items = re.split(r"[,|]", raw) if raw else []
    return tuple(item.strip() for item in raw_items if item.strip())


def parse_vmess_link(link: str) -> VmessConfig:
    if not isinstance(link, str) or not link.lower().startswith("vmess://"):
        raise AppError("not a VMess link")
    decoded = decode_base64_text(unquote(link[8:].strip()))
    if not decoded:
        raise AppError("invalid base64 payload")
    try:
        data = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise AppError("invalid VMess JSON: %s" % exc.msg) from exc
    if not isinstance(data, dict):
        raise AppError("VMess payload must be a JSON object")

    address = clean_text(data.get("add"))
    port = parse_port(data.get("port"))
    user_id = clean_text(data.get("id"))
    if not address or any(ch.isspace() for ch in address):
        raise AppError("missing or invalid server address")
    if port is None:
        raise AppError("missing or invalid server port")
    if not user_id:
        raise AppError("missing VMess user id")

    try:
        alter_id = max(0, int(clean_text(data.get("aid")) or "0"))
    except ValueError:
        alter_id = 0

    tls_value = clean_text(data.get("tls")).lower()
    security = "tls" if tls_value in {"tls", "xtls"} else "none"
    sni = clean_text(data.get("sni")) or clean_text(data.get("host"))
    allow_insecure = parse_bool(data.get("allowInsecure"))
    return VmessConfig(
        raw=link,
        address=address,
        port=port,
        user_id=user_id,
        alter_id=alter_id,
        cipher=(clean_text(data.get("scy")) or "auto").lower(),
        network=normalize_network(clean_text(data.get("net"))),
        transport_security=security,
        sni=sni,
        host=clean_text(data.get("host")),
        path=clean_text(data.get("path")) or "/",
        service_name=clean_text(data.get("serviceName")) or clean_text(data.get("path")),
        authority=clean_text(data.get("authority")) or clean_text(data.get("host")),
        alpn=parse_alpn(data.get("alpn")),
        fingerprint=clean_text(data.get("fp")) or "chrome",
        allow_insecure=allow_insecure,
        remark=clean_text(data.get("ps")),
        header_type=clean_text(data.get("type")) or "none",
    )


def read_text_file(path: str) -> str:
    if not path:
        return ""
    try:
        return Path(path).expanduser().read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise AppError("cannot read file %s: %s" % (path, exc)) from exc


def is_github_host(hostname: str) -> bool:
    host = hostname.lower().rstrip(".")
    return host == "github.com" or host == "api.github.com" or host.endswith(".githubusercontent.com")


def fetch_source(url: str, session: requests.Session, retries: int,
                 timeout: float, verbose: bool) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AppError("invalid source URL")
    headers: Dict[str, str] = {}
    if GITHUB_TOKEN and is_github_host(parsed.hostname):
        headers["Authorization"] = "Bearer %s" % GITHUB_TOKEN
    last_error = "unknown error"
    for attempt in range(retries + 1):
        try:
            with session.get(url, headers=headers, timeout=timeout,
                             stream=True, allow_redirects=True) as response:
                response.raise_for_status()
                chunks: List[bytes] = []
                total = 0
                for chunk in response.iter_content(65536):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > MAX_SOURCE_BYTES:
                        raise AppError("source exceeds size limit")
                    chunks.append(chunk)
                return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
        except (requests.RequestException, AppError) as exc:
            last_error = str(exc)
            if verbose:
                log("[SOURCE RETRY] %s: %s" % (url, last_error))
            if attempt < retries:
                time.sleep(min(8.0, 1.5 * (2 ** attempt)))
    raise AppError(last_error)


def collect_links(sources: Sequence[str], seed_file: str, session: requests.Session,
                  retries: int, timeout: float, verbose: bool) -> Set[str]:
    links: Set[str] = set()
    if seed_file:
        links.update(extract_links_from_subscription(read_text_file(seed_file)))
    for index, source in enumerate(sources, 1):
        try:
            text = fetch_source(source, session, retries, timeout, verbose)
            found = extract_links_from_subscription(text)
            links.update(found)
            log("[SOURCE %d/%d] %d links" % (index, len(sources), len(found)))
        except AppError as exc:
            log("[SOURCE %d/%d] failed: %s" % (index, len(sources), exc))
    return links


def find_xray_executable(explicit: str) -> Path:
    candidates = [explicit, XRAY_PATH_ENV, shutil.which("xray") or "",
                  shutil.which("xray.exe") or ""]
    for candidate in candidates:
        if candidate:
            path = Path(candidate).expanduser().resolve()
            if path.is_file():
                return path
    raise AppError("xray executable was not found; use --xray or XRAY_PATH")


def get_xray_version(path: Path) -> str:
    try:
        result = subprocess.run([str(path), "version"], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=8,
                                check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AppError("cannot execute Xray: %s" % exc) from exc
    first_line = (result.stdout or "").strip().splitlines()
    if result.returncode != 0 or not first_line:
        raise AppError("Xray version command failed")
    return first_line[0]


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def transport_settings(config: VmessConfig) -> Dict[str, object]:
    if config.network == "websocket":
        return {"wsSettings": {"path": config.path,
                               "headers": {"Host": config.host} if config.host else {}}}
    if config.network == "grpc":
        settings: Dict[str, object] = {"serviceName": config.service_name}
        if config.authority:
            settings["authority"] = config.authority
        return {"grpcSettings": settings}
    if config.network == "httpupgrade":
        return {"httpupgradeSettings": {"path": config.path,
                                         "host": config.host or config.authority}}
    if config.network == "xhttp":
        return {"xhttpSettings": {"path": config.path,
                                   "host": config.host or config.authority,
                                   "mode": "auto"}}
    if config.network == "mkcp":
        return {"kcpSettings": {"header": {"type": config.header_type}}}
    return {"rawSettings": {"header": {"type": config.header_type}}}


def build_xray_config(config: VmessConfig, socks_port: int,
                      allow_insecure_override: bool) -> Dict[str, object]:
    stream: Dict[str, object] = {
        "network": config.network,
        "security": config.transport_security,
    }
    stream.update(transport_settings(config))
    if config.transport_security == "tls":
        tls: Dict[str, object] = {
            "serverName": config.sni or config.address,
            "allowInsecure": bool(config.allow_insecure or allow_insecure_override),
            "fingerprint": config.fingerprint,
        }
        if config.alpn:
            tls["alpn"] = list(config.alpn)
        stream["tlsSettings"] = tls

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{
            "tag": "vmess-out",
            "protocol": "vmess",
            "settings": {"vnext": [{
                "address": config.address,
                "port": config.port,
                "users": [{
                    "id": config.user_id,
                    "alterId": config.alter_id,
                    "security": config.cipher if config.cipher else "auto",
                }],
            }]},
            "streamSettings": stream,
        }, {"tag": "direct", "protocol": "freedom"}],
        "routing": {"domainStrategy": "AsIs", "rules": [{
            "type": "field", "inboundTag": ["socks-in"],
            "outboundTag": "vmess-out",
        }]},
    }


def wait_for_port(port: int, process: subprocess.Popen, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.08)
    return False


def terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def calculate_score(probes: Sequence[ProbeResult], insecure_tls: bool) -> Tuple[int, float, Optional[float]]:
    if not probes:
        return 0, 0.0, None
    successes = [item for item in probes if item.success and item.elapsed_ms is not None]
    rate = len(successes) / float(len(probes))
    if not successes:
        return 0, rate, None
    latencies = [float(item.elapsed_ms) for item in successes if item.elapsed_ms is not None]
    median = statistics.median(latencies)
    if median <= 500:
        latency_points = 20
    elif median <= 1000:
        latency_points = 16
    elif median <= 2000:
        latency_points = 11
    elif median <= 4000:
        latency_points = 6
    else:
        latency_points = 2
    if len(latencies) <= 1:
        stability_points = 10
    else:
        deviation = statistics.pstdev(latencies)
        stability_points = 10 if deviation <= 250 else 6 if deviation <= 750 else 2
    score = min(100, int(round(rate * 70)) + latency_points + stability_points)
    if insecure_tls:
        score = max(0, score - 10)
    return score, rate, float(median)


def test_config(config: VmessConfig, xray: Path, attempts: int,
                urls: Sequence[str], request_timeout: float,
                startup_timeout: float, min_score: int,
                allow_insecure_override: bool, verbose: bool) -> LinkResult:
    port = free_tcp_port()
    probes: List[ProbeResult] = []
    with tempfile.TemporaryDirectory(prefix="vmess-test-") as temp_dir:
        config_path = Path(temp_dir) / "config.json"
        config_path.write_text(json.dumps(
            build_xray_config(config, port, allow_insecure_override),
            ensure_ascii=False, indent=2), encoding="utf-8")

        validation = subprocess.run(
            [str(xray), "run", "-test", "-c", str(config_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=max(6.0, startup_timeout), check=False)
        if validation.returncode != 0:
            return LinkResult(config.dedup_key, config.raw, config.address,
                              config.port, config.network, config.transport_security,
                              config.remark, 0, 0.0, None, False, "validation",
                              (validation.stdout or "Xray validation failed").strip()[-1200:])

        process = subprocess.Popen(
            [str(xray), "run", "-c", str(config_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
        try:
            if not wait_for_port(port, process, startup_timeout):
                output = ""
                if process.poll() is not None and process.stdout:
                    output = process.stdout.read()
                return LinkResult(config.dedup_key, config.raw, config.address,
                                  config.port, config.network, config.transport_security,
                                  config.remark, 0, 0.0, None, False, "startup",
                                  (output or "local SOCKS inbound did not start").strip()[-1200:])

            session = requests.Session()
            session.trust_env = False
            proxy = "socks5h://127.0.0.1:%d" % port
            session.proxies.update({"http": proxy, "https": proxy})
            try:
                for index in range(attempts):
                    url = urls[index % len(urls)]
                    started = time.perf_counter()
                    try:
                        response = session.get(url, timeout=request_timeout,
                                               allow_redirects=False, stream=True)
                        payload = response.raw.read(4096, decode_content=True)
                        elapsed = (time.perf_counter() - started) * 1000.0
                        success = 200 <= response.status_code < 400
                        probes.append(ProbeResult(url, success, response.status_code,
                                                  elapsed, len(payload),
                                                  "" if success else "HTTP %d" % response.status_code))
                    except requests.RequestException as exc:
                        elapsed = (time.perf_counter() - started) * 1000.0
                        probes.append(ProbeResult(url, False, None, elapsed, 0,
                                                  "%s: %s" % (type(exc).__name__, exc)))
            finally:
                session.close()
        finally:
            terminate_process(process)

    insecure = bool(config.allow_insecure or allow_insecure_override)
    score, rate, median = calculate_score(probes, insecure)
    accepted = score >= min_score and any(probe.success for probe in probes)
    errors = [probe.error for probe in probes if probe.error]
    if verbose and errors:
        log("[PROBE] %s:%d %s" % (config.address, config.port, errors[-1]))
    return LinkResult(config.dedup_key, config.raw, config.address, config.port,
                      config.network, config.transport_security, config.remark,
                      score, rate, median, accepted,
                      "" if accepted else "request", errors[-1] if errors else "",
                      probes)


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="",
                                     delete=False, dir=str(path.parent),
                                     prefix=path.name + ".", suffix=".tmp") as handle:
        handle.write(content)
        temp_name = handle.name
    os.replace(temp_name, str(path))


def write_outputs(prefix: Path, accepted: Sequence[LinkResult],
                  all_results: Sequence[LinkResult], metadata: Dict[str, object]) -> Tuple[Path, Path, Path]:
    txt_path = prefix.with_name(prefix.name + "_vmess.txt")
    json_path = prefix.with_name(prefix.name + "_report.json")
    csv_path = prefix.with_name(prefix.name + "_report.csv")
    atomic_write(txt_path, "".join(item.link + "\n" for item in accepted))
    atomic_write(json_path, json.dumps({"metadata": metadata,
                                        "results": [item.to_dict() for item in all_results]},
                                       ensure_ascii=False, indent=2) + "\n")
    rows = []
    for item in all_results:
        rows.append({
            "accepted": item.accepted, "score": item.score,
            "success_rate": round(item.success_rate, 4),
            "median_latency_ms": item.median_latency_ms,
            "address": item.address, "port": item.port,
            "network": item.network, "security": item.transport_security,
            "remark": item.remark, "error_stage": item.error_stage,
            "error": item.error,
        })
    fieldnames = list(rows[0]) if rows else ["accepted", "score", "success_rate",
                                             "median_latency_ms", "address", "port",
                                             "network", "security", "remark",
                                             "error_stage", "error"]
    temp = tempfile.NamedTemporaryFile("w", encoding="utf-8-sig", newline="",
                                       delete=False, dir=str(csv_path.parent),
                                       prefix=csv_path.name + ".", suffix=".tmp")
    try:
        writer = csv.DictWriter(temp, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        temp.close()
        os.replace(temp.name, str(csv_path))
    finally:
        if not temp.closed:
            temp.close()
        if os.path.exists(temp.name):
            os.unlink(temp.name)
    return txt_path, json_path, csv_path


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
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
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
    parser.add_argument("--output-prefix", default="v2ray_quality")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    profile = dict(PROFILES[args.profile])
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
    version = get_xray_version(xray)
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

    source_session = requests.Session()
    source_session.headers["User-Agent"] = "Iran-VMess-E2E-Tester/%s" % APP_VERSION
    source_session.trust_env = not bool(args.source_proxy)
    if args.source_proxy:
        source_session.proxies.update({"http": args.source_proxy, "https": args.source_proxy})
    try:
        raw_links = collect_links(sorted(sources), args.seed_file, source_session,
                                  retries, args.source_timeout, args.verbose)
    finally:
        source_session.close()

    parsed: Dict[str, VmessConfig] = {}
    failures: List[LinkResult] = []
    for link in sorted(raw_links):
        try:
            config = parse_vmess_link(link)
            parsed.setdefault(config.dedup_key, config)
        except AppError as exc:
            failures.append(LinkResult(hashlib.sha256(link.encode()).hexdigest(),
                                       link, "", 0, "", "", "", 0, 0.0,
                                       None, False, "parse", str(exc)))
    configs = list(parsed.values())
    if args.sample and len(configs) > args.sample:
        random.SystemRandom().shuffle(configs)
        configs = configs[:args.sample]

    log("VMess End-to-End Tester v%s | %s" % (APP_VERSION, version))
    log("Collected=%d Unique=%d Testing=%d" % (len(raw_links), len(parsed), len(configs)))
    results: List[LinkResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(test_config, config, xray, attempts, urls,
                            request_timeout, startup_timeout, min_score,
                            args.allow_insecure_server_cert, args.verbose): config
            for config in configs
        }
        for count, future in enumerate(concurrent.futures.as_completed(future_map), 1):
            config = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                result = LinkResult(config.dedup_key, config.raw, config.address,
                                    config.port, config.network,
                                    config.transport_security, config.remark,
                                    0, 0.0, None, False, "worker",
                                    "%s: %s" % (type(exc).__name__, exc))
            results.append(result)
            latency = "-" if result.median_latency_ms is None else "%.0fms" % result.median_latency_ms
            log("[%d/%d] %s score=%d latency=%s %s:%d" %
                (count, len(configs), "PASS" if result.accepted else "FAIL",
                 result.score, latency, result.address, result.port))

    accepted = sorted((item for item in results if item.accepted),
                      key=lambda item: (-item.score,
                                        item.median_latency_ms if item.median_latency_ms is not None else float("inf"),
                                        item.address))
    if args.topk:
        accepted = accepted[:args.topk]
    complete = sorted(failures + results,
                      key=lambda item: (not item.accepted, -item.score,
                                        item.address, item.port))
    metadata: Dict[str, object] = {
        "app_version": APP_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "profile": args.profile,
        "xray_path": str(xray),
        "xray_version": version,
        "workers": workers,
        "attempts": attempts,
        "request_timeout": request_timeout,
        "startup_timeout": startup_timeout,
        "min_score": min_score,
        "test_urls": urls,
        "raw_links": len(raw_links),
        "unique_configs": len(parsed),
    }
    txt_path, json_path, csv_path = write_outputs(Path(args.output_prefix), accepted,
                                                   complete, metadata)
    log("Accepted=%d Tested=%d ParseFailures=%d" %
        (len(accepted), len(results), len(failures)))
    log("TXT=%s\nJSON=%s\nCSV=%s" % (txt_path, json_path, csv_path))
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
