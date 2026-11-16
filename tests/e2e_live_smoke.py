# -*- coding: utf-8 -*-
"""Controlled integration smoke test: local Xray VLESS server, real HTTPS probes.

This script is intentionally excluded from unittest discovery. It needs an
explicit XRAY_PATH and outbound HTTPS access. Nothing is published or logged
about real third-party proxy credentials.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from vmess_types import parse_link
from vmess_xray import STOP_EVENT, test_config


TEST_URLS = (
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
)


def _unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        return int(server.getsockname()[1])


def _wait_listening(port: int, process: subprocess.Popen, seconds: float) -> None:
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError("controlled Xray server exited unexpectedly")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("controlled Xray server did not bind")


def _check(config_link: str, xray: Path):
    config = parse_link(config_link)
    return test_config(
        config=config,
        xray=xray,
        attempts=3,
        urls=TEST_URLS,
        request_timeout=12.0,
        startup_timeout=7.0,
        min_score=0,  # Verify admission evidence, not performance rank.
        allow_insecure_override=False,
        verbose=False,
        tcp_precheck=True,
        deep_test=False,
    )


def main() -> int:
    xray = Path(os.environ["XRAY_PATH"]).resolve()
    if not xray.is_file():
        raise RuntimeError("XRAY_PATH does not refer to a regular file")
    STOP_EVENT.clear()
    identity = str(uuid.uuid4())
    negative_identity = str(uuid.uuid4())
    port = _unused_port()
    server_config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [{"id": identity}], "decryption": "none"},
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }

    with tempfile.TemporaryDirectory(prefix="xray-controlled-smoke-") as directory:
        root = Path(directory)
        conf = root / "server.json"
        conf.write_text(json.dumps(server_config), encoding="utf-8")
        with (root / "server.log").open("wb") as logfile:
            process = subprocess.Popen(
                [str(xray), "run", "-c", str(conf)],
                stdin=subprocess.DEVNULL, stdout=logfile,
                stderr=subprocess.STDOUT,
            )
            try:
                _wait_listening(port, process, 12.0)
                good = "vless://%s@127.0.0.1:%d?encryption=none&security=none&type=tcp#smoke" % (
                    identity, port
                )
                bad = "vless://%s@127.0.0.1:%d?encryption=none&security=none&type=tcp#smoke" % (
                    negative_identity, port
                )
                accepted = _check(good, xray)
                rejected = _check(bad, xray)
                print("Controlled positive: verified=%s, primary=%d/%d" % (
                    accepted.accepted,
                    sum(bool(p.success) for p in accepted.probes),
                    len(accepted.probes),
                ))
                print("Controlled negative: verified=%s, primary=%d/%d" % (
                    rejected.accepted,
                    sum(bool(p.success) for p in rejected.probes),
                    len(rejected.probes),
                ))
                if not accepted.accepted:
                    raise RuntimeError(
                        "positive VLESS loopback control did not pass HTTPS verification "
                        "(inspect network access and Xray version on the runner)"
                    )
                if rejected.accepted:
                    raise RuntimeError("invalid-credential negative control was accepted")
                print("Controlled Xray end-to-end smoke: PASS")
                return 0
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, OSError, RuntimeError, ValueError) as exc:
        print("Controlled Xray end-to-end smoke: FAILED (%s)" % type(exc).__name__,
              file=sys.stderr)
        sys.exit(1)
