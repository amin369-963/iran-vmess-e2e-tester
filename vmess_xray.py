# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Sequence, Set, Tuple

import requests

from vmess_types import AppError, LinkResult, ProbeResult, ProxyConfig, calculate_score

XRAY_PATH_ENV = os.getenv("XRAY_PATH", "").strip()
SCRIPT_DIR = Path(__file__).resolve().parent
CREATION_FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

# Global cancellation state shared by all worker threads.
STOP_EVENT = threading.Event()
_STATE_LOCK = threading.Lock()
_ACTIVE_PROCESSES: Set[subprocess.Popen] = set()
_RESERVED_PORTS: Set[int] = set()

PORT_RETRY_LIMIT = 3
LOG_TAIL_BYTES = 64 * 1024
PORT_IN_USE_MARKERS = (
    "address already in use",
    "only one usage of each socket address",
    "failed to listen",
)


# --------------------------------------------------------------------------- #
# Xray discovery
# --------------------------------------------------------------------------- #

def _executable_names() -> Tuple[str, ...]:
    return ("xray.exe", "xray") if os.name == "nt" else ("xray", "xray.exe")


def find_xray_executable(explicit: str) -> Path:
    names = _executable_names()
    if explicit:
        path = Path(explicit).expanduser()
        if path.is_dir():
            for name in names:
                if (path / name).is_file():
                    return (path / name).resolve()
        if path.is_file():
            return path.resolve()
        raise AppError("xray executable was not found at %s" % explicit)

    candidates: List[Path] = []
    if XRAY_PATH_ENV:
        candidates.append(Path(XRAY_PATH_ENV).expanduser())
    for base in (SCRIPT_DIR, SCRIPT_DIR / "Xray", Path.cwd(), Path.cwd() / "Xray"):
        candidates.extend(base / name for name in names)
    for name in names:
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise AppError("xray executable was not found; place it next to main.py, "
                   "or use --xray / XRAY_PATH")


def get_xray_version(path: Path) -> str:
    try:
        result = subprocess.run([str(path), "version"], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=8,
                                check=False, creationflags=CREATION_FLAGS)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AppError("cannot execute Xray: %s" % exc) from exc
    first_line = (result.stdout or "").strip().splitlines()
    if result.returncode != 0 or not first_line:
        raise AppError("Xray version command failed")
    return first_line[0]


# --------------------------------------------------------------------------- #
# Port reservation and process tracking
# --------------------------------------------------------------------------- #

def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def reserve_port() -> int:
    """Return a free local port that no other worker of this run is using."""
    for _ in range(100):
        port = free_tcp_port()
        with _STATE_LOCK:
            if port not in _RESERVED_PORTS:
                _RESERVED_PORTS.add(port)
                return port
    raise AppError("could not reserve a free local port")


def release_port(port: int) -> None:
    with _STATE_LOCK:
        _RESERVED_PORTS.discard(port)


def _register_process(process: subprocess.Popen) -> bool:
    with _STATE_LOCK:
        if STOP_EVENT.is_set():
            return False
        _ACTIVE_PROCESSES.add(process)
        return True


def _unregister_process(process: subprocess.Popen) -> None:
    with _STATE_LOCK:
        _ACTIVE_PROCESSES.discard(process)


def stop_all_processes() -> None:
    """Signal every worker to stop and kill all running Xray processes."""
    STOP_EVENT.set()
    with _STATE_LOCK:
        processes = list(_ACTIVE_PROCESSES)
    for process in processes:
        try:
            if process.poll() is None:
                process.kill()
        except OSError:
            pass


def terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def tcp_reachable(address: str, port: int, timeout: float) -> bool:
    """Quick TCP connect pre-filter; rejects unreachable servers without spawning Xray."""
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# Xray configuration
# --------------------------------------------------------------------------- #

def transport_settings(config: ProxyConfig) -> Dict[str, object]:
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


def build_stream_settings(config: ProxyConfig, allow_insecure_override: bool) -> Dict[str, object]:
    stream: Dict[str, object] = {
        "network": config.network,
        "security": config.transport_security,
    }
    stream.update(transport_settings(config))
    if config.transport_security == "tls":
        tls: Dict[str, object] = {
            "serverName": config.sni or config.address,
            "allowInsecure": bool(config.allow_insecure or allow_insecure_override),
            "fingerprint": config.fingerprint or "chrome",
        }
        if config.alpn:
            tls["alpn"] = list(config.alpn)
        stream["tlsSettings"] = tls
    elif config.transport_security == "reality":
        stream["realitySettings"] = {
            "serverName": config.sni or config.address,
            "fingerprint": config.fingerprint or "chrome",
            "publicKey": config.public_key,
            "shortId": config.short_id,
            "spiderX": config.spider_x,
        }
    return stream


def build_outbound_settings(config: ProxyConfig) -> Dict[str, object]:
    if config.protocol == "vmess":
        return {"vnext": [{
            "address": config.address, "port": config.port,
            "users": [{"id": config.user_id, "alterId": config.alter_id,
                       "security": config.cipher or "auto"}],
        }]}
    if config.protocol == "vless":
        user: Dict[str, object] = {"id": config.user_id,
                                   "encryption": config.encryption or "none"}
        if config.flow:
            user["flow"] = config.flow
        return {"vnext": [{"address": config.address, "port": config.port,
                           "users": [user]}]}
    if config.protocol == "trojan":
        return {"servers": [{"address": config.address, "port": config.port,
                             "password": config.password}]}
    if config.protocol == "shadowsocks":
        return {"servers": [{"address": config.address, "port": config.port,
                             "method": config.method, "password": config.password}]}
    raise AppError("unsupported protocol: %s" % config.protocol)


def build_xray_config(config: ProxyConfig, socks_port: int,
                      allow_insecure_override: bool) -> Dict[str, object]:
    outbound: Dict[str, object] = {
        "tag": "proxy-out", "protocol": config.protocol,
        "settings": build_outbound_settings(config),
    }
    if config.protocol != "shadowsocks":
        outbound["streamSettings"] = build_stream_settings(config, allow_insecure_override)
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
            "protocol": "socks", "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [outbound, {"tag": "direct", "protocol": "freedom"}],
        "routing": {"domainStrategy": "AsIs", "rules": [{
            "type": "field", "inboundTag": ["socks-in"], "outboundTag": "proxy-out",
        }]},
    }


def build_probe_plan(urls: Sequence[str], minimum_attempts: int) -> List[str]:
    """Return complete URL cycles so every endpoint has equal weight."""
    if not urls:
        raise AppError("at least one test URL is required")
    if minimum_attempts < 1:
        raise AppError("attempts must be at least 1")
    rounds = (minimum_attempts + len(urls) - 1) // len(urls)
    return [url for _ in range(rounds) for url in urls]


# --------------------------------------------------------------------------- #
# Test execution
# --------------------------------------------------------------------------- #

def wait_for_port(port: int, process: subprocess.Popen, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if STOP_EVENT.is_set() or process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.08)
    return False


def _read_log_tail(path: Path) -> str:
    try:
        with path.open("rb") as file_obj:
            file_obj.seek(0, os.SEEK_END)
            size = file_obj.tell()
            file_obj.seek(max(0, size - LOG_TAIL_BYTES))
            return file_obj.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _failure(config: ProxyConfig, stage: str, error: str) -> LinkResult:
    return LinkResult(config.dedup_key, config.raw, config.address, config.port,
                      config.network, config.transport_security, config.remark,
                      0, 0.0, None, False, stage, error, [], protocol=config.protocol)


def _run_probes(port: int, probe_plan: Sequence[str],
                request_timeout: float) -> List[ProbeResult]:
    probes: List[ProbeResult] = []
    session = requests.Session()
    session.trust_env = False
    proxy = "socks5h://127.0.0.1:%d" % port
    session.proxies.update({"http": proxy, "https": proxy})
    try:
        for url in probe_plan:
            if STOP_EVENT.is_set():
                break
            started = time.perf_counter()
            try:
                response = session.get(url, timeout=request_timeout,
                                       allow_redirects=False, stream=True)
                payload = response.raw.read(4096, decode_content=True)
                response.close()
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
    return probes


def _deep_quality_assessment(
    port: int,
    request_timeout: float,
    test_speed: bool = True,
    test_blocked: bool = True,
) -> Tuple[float, str, str, int]:
    """Assess real network quality: IP, Country, YouTube access, and Download speed."""
    session = requests.Session()
    session.trust_env = False
    proxy = "socks5h://127.0.0.1:%d" % port
    session.proxies.update({"http": proxy, "https": proxy})

    country = ""
    ip = ""
    blocked_passed = 0
    speed_kbps = 0.0

    try:
        # 1. Cloudflare trace to find IP & Country
        try:
            resp = session.get("https://www.cloudflare.com/cdn-cgi/trace", timeout=min(6.0, request_timeout))
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    if line.startswith("ip="):
                        ip = line.split("=", 1)[1].strip()
                    elif line.startswith("loc="):
                        country = line.split("=", 1)[1].strip()
        except Exception:
            pass

        # 2. Blocked site probe (YouTube)
        if test_blocked and not STOP_EVENT.is_set():
            try:
                resp = session.get("https://www.youtube.com/generate_204", timeout=min(6.0, request_timeout), allow_redirects=False)
                if 200 <= resp.status_code < 400:
                    blocked_passed += 1
            except Exception:
                pass

        # 3. Speed test (download up to 512 KB to quickly measure throughput without wasting bandwidth)
        if test_speed and not STOP_EVENT.is_set():
            speed_url = "https://speed.cloudflare.com/__down?bytes=524288"
            started = time.perf_counter()
            total_bytes = 0
            try:
                with session.get(speed_url, timeout=min(8.0, request_timeout), stream=True) as resp:
                    if resp.status_code == 200:
                        for chunk in resp.iter_content(chunk_size=16384):
                            if STOP_EVENT.is_set():
                                break
                            if chunk:
                                total_bytes += len(chunk)
                duration = time.perf_counter() - started
                if duration > 0.05 and total_bytes > 0:
                    speed_kbps = round((total_bytes / 1024.0) / duration, 1)
            except Exception:
                pass
    finally:
        session.close()

    return speed_kbps, country, ip, blocked_passed


def _run_once(config: ProxyConfig, xray: Path, temp_dir: Path, port: int,
              probe_plan: Sequence[str], request_timeout: float,
              startup_timeout: float, allow_insecure_override: bool,
              deep_test: bool = True,
              ) -> Tuple[str, str, List[ProbeResult], bool, float, str, str, int]:
    """Run one Xray instance. Returns (stage, error, probes, port_conflict, speed, country, ip, blocked_passed)."""
    config_path = temp_dir / "config.json"
    log_path = temp_dir / "xray.log"
    config_path.write_text(json.dumps(build_xray_config(config, port, allow_insecure_override),
                                      ensure_ascii=False, indent=2), encoding="utf-8")

    with log_path.open("w", encoding="utf-8", errors="replace") as log_file:
        process = subprocess.Popen([str(xray), "run", "-c", str(config_path)],
                                   stdout=log_file, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, creationflags=CREATION_FLAGS)
        if not _register_process(process):
            terminate_process(process)
            return "cancelled", "run interrupted", [], False, 0.0, "", "", 0
        try:
            if not wait_for_port(port, process, startup_timeout):
                terminate_process(process)
                if STOP_EVENT.is_set():
                    return "cancelled", "run interrupted", [], False, 0.0, "", "", 0
                output = _read_log_tail(log_path)
                conflict = any(marker in output.lower() for marker in PORT_IN_USE_MARKERS)
                stage = "startup"
                if not output.strip():
                    validation = subprocess.run(
                        [str(xray), "run", "-test", "-c", str(config_path)],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                        timeout=max(6.0, startup_timeout), check=False,
                        creationflags=CREATION_FLAGS)
                    if validation.returncode != 0:
                        output = validation.stdout or "Xray validation failed"
                        stage = "validation"
                return (stage, (output or "local SOCKS inbound did not start").strip()[-1200:],
                        [], conflict, 0.0, "", "", 0)

            probes = _run_probes(port, probe_plan, request_timeout)
            speed_kbps, country, ip, blocked_passed = 0.0, "", "", 0
            if deep_test and any(p.success for p in probes) and not STOP_EVENT.is_set():
                speed_kbps, country, ip, blocked_passed = _deep_quality_assessment(port, request_timeout)

            return "", "", probes, False, speed_kbps, country, ip, blocked_passed
        finally:
            terminate_process(process)
            _unregister_process(process)


def test_config(config: ProxyConfig, xray: Path, attempts: int,
                urls: Sequence[str], request_timeout: float,
                startup_timeout: float, min_score: int,
                allow_insecure_override: bool, verbose: bool, logger=print,
                tcp_precheck: bool = True, tcp_timeout: float = 3.0,
                deep_test: bool = True) -> LinkResult:
    if STOP_EVENT.is_set():
        return _failure(config, "cancelled", "run interrupted")
    if tcp_precheck and not tcp_reachable(config.address, config.port, tcp_timeout):
        return _failure(config, "unreachable",
                        "TCP connect to server failed within %.1fs" % tcp_timeout)
    if STOP_EVENT.is_set():
        return _failure(config, "cancelled", "run interrupted")

    probe_plan = build_probe_plan(urls, attempts)
    stage, error, probes = "startup", "", []  # type: Tuple[str, str, List[ProbeResult]]
    speed_kbps, country, ip, blocked_passed = 0.0, "", "", 0

    with tempfile.TemporaryDirectory(prefix="xray-test-") as temp_name:
        temp_dir = Path(temp_name)
        for _ in range(PORT_RETRY_LIMIT):
            port = reserve_port()
            try:
                stage, error, probes, conflict, speed_kbps, country, ip, blocked_passed = _run_once(
                    config, xray, temp_dir, port, probe_plan, request_timeout,
                    startup_timeout, allow_insecure_override, deep_test=deep_test)
            finally:
                release_port(port)
            if not conflict:
                break
            if verbose:
                logger("[PORT] local port %d was taken; retrying" % port)

    if stage:
        return _failure(config, stage, error)
    if STOP_EVENT.is_set() and len(probes) < len(probe_plan):
        return _failure(config, "cancelled", "run interrupted")

    insecure = config.transport_security == "tls" and bool(
        config.allow_insecure or allow_insecure_override)
    score, rate, median = calculate_score(
        probes,
        insecure,
        speed_kbps=speed_kbps,
        blocked_sites_passed=blocked_passed,
    )
    accepted = score >= min_score and any(probe.success for probe in probes)
    errors = [probe.error for probe in probes if probe.error]
    if verbose and errors:
        logger("[PROBE] %s:%d %s" % (config.address, config.port, errors[-1]))
    return LinkResult(config.dedup_key, config.raw, config.address, config.port,
                      config.network, config.transport_security, config.remark,
                      score, rate, median, accepted,
                      "" if accepted else "request", errors[-1] if errors else "", probes,
                      protocol=config.protocol,
                      speed_kbps=speed_kbps,
                      country=country,
                      ip=ip)


# --------------------------------------------------------------------------- #
# Live Multi-Config Balancer / Proxy Mode (Observatory + LeastPing Failover)
# --------------------------------------------------------------------------- #

def build_balancer_xray_config(
    configs: Sequence[ProxyConfig],
    socks_port: int = 10808,
    http_port: int = 10809,
    allow_insecure_override: bool = False,
    probe_url: str = "https://www.gstatic.com/generate_204",
    probe_interval: str = "15s",
) -> Dict[str, object]:
    """Construct an Xray configuration that load balances across configs with automated least-ping failover."""
    outbounds: List[Dict[str, object]] = []
    outbound_tags: List[str] = []

    for idx, cfg in enumerate(configs, 1):
        tag = f"proxy-{idx}"
        outbound: Dict[str, object] = {
            "tag": tag,
            "protocol": cfg.protocol,
            "settings": build_outbound_settings(cfg),
        }
        if cfg.protocol != "shadowsocks":
            outbound["streamSettings"] = build_stream_settings(cfg, allow_insecure_override)
        outbounds.append(outbound)
        outbound_tags.append(tag)

    # Freedom / Direct outbound
    outbounds.append({"tag": "direct", "protocol": "freedom"})

    inbounds: List[Dict[str, object]] = [
        {
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
        }
    ]
    if http_port and http_port != socks_port:
        inbounds.append({
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": http_port,
            "protocol": "http",
            "settings": {"allowTransparent": False},
        })

    balancer_tag = "auto-balancer"
    routing = {
        "domainStrategy": "AsIs",
        "balancers": [
            {
                "tag": balancer_tag,
                "selector": ["proxy-"],
                "strategy": {"type": "leastPing"},
            }
        ],
        "rules": [
            {
                "type": "field",
                "inboundTag": [inb["tag"] for inb in inbounds],
                "balancerTag": balancer_tag,
            }
        ],
    }

    observatory = {
        "subjectSelector": ["proxy-"],
        "probeURL": probe_url,
        "probeInterval": probe_interval,
        "enableConcurrency": True,
    }

    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": routing,
        "observatory": observatory,
    }
