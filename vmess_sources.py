# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Dict, Optional, Sequence, Set
from urllib.parse import urlparse

import requests

from vmess_types import APP_VERSION, AppError, extract_links_from_subscription
from vmess_telegram import collect_telegram_links, telegram_preview_url
from vmess_priority import source_label

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
MAX_SOURCE_BYTES = 12 * 1024 * 1024

DEFAULT_SOURCES = (
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/Mohammadgb0078/IRV2ray/main/vmess.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vmess.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/mehrtat/vless-collector/main/vless.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/mrdevmohamed/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
    "https://t.me/s/daily_configs",
    "https://t.me/s/vpnfail_v2ray",
    "https://t.me/s/v2raycollector",
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


def read_text_file(path: str) -> str:
    if not path:
        return ""
    try:
        return Path(path).expanduser().read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise AppError("cannot read file %s: %s" % (path, exc)) from exc


def should_attach_github_token(hostname: str) -> bool:
    host = hostname.lower().rstrip(".")
    return host in {"github.com", "api.github.com"}


def build_source_session(proxy_url: str) -> requests.Session:
    session = requests.Session()
    session.headers["User-Agent"] = "Iran-Proxy-E2E-Tester/%s" % APP_VERSION
    session.trust_env = False
    if proxy_url:
        session.proxies.update({"http": proxy_url, "https": proxy_url})
    return session


def fetch_source(url: str, session: requests.Session, retries: int,
                 timeout: float, verbose: bool, logger=print) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AppError("invalid source URL")
    headers: Dict[str, str] = {}
    if GITHUB_TOKEN and should_attach_github_token(parsed.hostname):
        headers["Authorization"] = "Bearer %s" % GITHUB_TOKEN
    last_error = "unknown error"
    for attempt in range(retries + 1):
        try:
            with session.get(url, headers=headers, timeout=timeout,
                             stream=True, allow_redirects=True) as response:
                response.raise_for_status()
                chunks = []
                total = 0
                for chunk in response.iter_content(65536):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > MAX_SOURCE_BYTES:
                        raise AppError("source exceeds size limit")
                    chunks.append(chunk)
                return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
        except requests.HTTPError as exc:
            last_error = str(exc)
            status = exc.response.status_code if exc.response is not None else None
            if status in {404, 410}:
                raise AppError(last_error) from exc
            if verbose:
                logger("[SOURCE RETRY] %s: %s" % (url, last_error))
            if attempt < retries:
                time.sleep(min(8.0, 1.5 * (2 ** attempt)))
        except (requests.RequestException, AppError) as exc:
            last_error = str(exc)
            if verbose:
                logger("[SOURCE RETRY] %s: %s" % (url, last_error))
            if attempt < retries:
                time.sleep(min(8.0, 1.5 * (2 ** attempt)))
    raise AppError(last_error)


def collect_links(sources: Sequence[str], seed_file: str, session: requests.Session,
                  retries: int, timeout: float, verbose: bool, logger=print,
                  source_links: Optional[Dict[str, Set[str]]] = None,
                  telegram_limit: int = 50, telegram_hours: int = 24,
                  protocols: Optional[Set[str]] = None) -> Set[str]:
    links: Set[str] = set()
    if seed_file:
        seeded = set(extract_links_from_subscription(read_text_file(seed_file)))
        links.update(seeded)
        if source_links is not None:
            source_links["seed:" + Path(seed_file).name] = seeded
    for index, source in enumerate(sources, 1):
        if source_links is not None:
            source_links[source] = set()
        try:
            if telegram_preview_url(source) is not None:
                found = collect_telegram_links(
                    source, lambda page: fetch_source(page, session, retries, timeout, verbose, logger),
                    telegram_limit, telegram_hours, logger=logger, protocols=protocols,
                )
            else:
                text = fetch_source(source, session, retries, timeout, verbose, logger)
                found = extract_links_from_subscription(text)
            links.update(found)
            if source_links is not None:
                source_links[source].update(found)
            logger("[SOURCE %d/%d] %s: %d links" % (index, len(sources), source_label(source), len(found)))
        except AppError as exc:
            logger("[SOURCE %d/%d] %s failed: %s" % (index, len(sources), source_label(source), exc))
    return links
