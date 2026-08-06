# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Sequence

import requests

from vmess_types import AppError, LinkResult, ProbeResult, VmessConfig, calculate_score

XRAY_PATH_ENV = os.getenv("XRAY_PATH", "").strip()


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
            "tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
            "protocol": "socks", "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{
            "tag": "vmess-out", "protocol": "vmess",
            "settings": {"vnext": [{
                "address": config.address, "port": config.port,
                "users": [{"id": config.user_id, "alterId": config.alter_id,
                           "security": config.cipher or "auto"}],
            }]},
            "streamSettings": stream,
        }, {"tag": "direct", "protocol": "freedom"}],
        "routing": {"domainStrategy": "AsIs", "rules": [{
            "type": "field", "inboundTag": ["socks-in"], "outboundTag": "vmess-out",
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


def test_config(config: VmessConfig, xray: Path, attempts: int,
                urls: Sequence[str], request_timeout: float,
                startup_timeout: float, min_score: int,
                allow_insecure_override: bool, verbose: bool, logger=print) -> LinkResult:
    port = free_tcp_port()
    probes = []
    probe_plan = build_probe_plan(urls, attempts)
    with tempfile.TemporaryDirectory(prefix="vmess-test-") as temp_dir:
        config_path = Path(temp_dir) / "config.json"
        config_path.write_text(json.dumps(build_xray_config(config, port, allow_insecure_override),
                                          ensure_ascii=False, indent=2), encoding="utf-8")
        validation = subprocess.run([str(xray), "run", "-test", "-c", str(config_path)],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, timeout=max(6.0, startup_timeout), check=False)
        if validation.returncode != 0:
            return LinkResult(config.dedup_key, config.raw, config.address, config.port,
                              config.network, config.transport_security, config.remark,
                              0, 0.0, None, False, "validation",
                              (validation.stdout or "Xray validation failed").strip()[-1200:])

        process = subprocess.Popen([str(xray), "run", "-c", str(config_path)],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True,
                                   creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
        try:
            if not wait_for_port(port, process, startup_timeout):
                output = ""
                if process.poll() is not None and process.stdout:
                    output = process.stdout.read()
                return LinkResult(config.dedup_key, config.raw, config.address, config.port,
                                  config.network, config.transport_security, config.remark,
                                  0, 0.0, None, False, "startup",
                                  (output or "local SOCKS inbound did not start").strip()[-1200:])

            session = requests.Session()
            session.trust_env = False
            proxy = "socks5h://127.0.0.1:%d" % port
            session.proxies.update({"http": proxy, "https": proxy})
            try:
                for url in probe_plan:
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
        logger("[PROBE] %s:%d %s" % (config.address, config.port, errors[-1]))
    return LinkResult(config.dedup_key, config.raw, config.address, config.port,
                      config.network, config.transport_security, config.remark,
                      score, rate, median, accepted,
                      "" if accepted else "request", errors[-1] if errors else "", probes)
