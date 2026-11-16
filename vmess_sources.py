# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import ipaddress
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Sequence, Set
from urllib.parse import urlparse

import requests

from vmess_types import APP_VERSION, AppError, extract_links_from_subscription, parse_link
from vmess_telegram import collect_telegram_links, telegram_preview_url
from vmess_priority import source_label

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
MAX_SOURCE_BYTES = 12 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_COUNT = 32
MAX_SOURCE_ELAPSED = 90.0
PILOT_SOURCE_BYTES = 2 * 1024 * 1024
PILOT_UNIQUE_LIMIT = 1500

# Explicit opt-in candidates; repository MIT licensing does not by itself
# authorize re-publication of individual share credentials.
PILOT_SOURCES = {
    "multi-fetcher": {
        "url": "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/main/configs/proxy_configs.txt",
        "tier": "LIGHT", "repo_license": "MIT",
    },
    "reference-verified": {
        "url": "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
        "tier": "LIGHT", "repo_license": "MIT",
    },
    "au1rxx": {
        "url": "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
        "tier": "LIGHT", "repo_license": "MIT",
    },
}
PILOT_IDS_BY_URL = {spec["url"]: name for name, spec in PILOT_SOURCES.items()}

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


def validate_source_url(url: str) -> None:
    """Reject clearly unsafe remote locations before opening any request."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise AppError("invalid source URL") from exc
    if (parsed.scheme != "https" or not host or parsed.username is not None
            or parsed.password is not None or parsed.fragment or port not in (None, 443)
            or "\\" in url or any(char.isspace() for char in url)):
        raise AppError("source must be HTTPS without userinfo, fragment or unsafe port")
    if (host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".test"))
            or host in {"metadata.google.internal"}):
        raise AppError("private source hostname is not allowed")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return
    if not ip.is_global:
        raise AppError("non-public source IP is not allowed")


def fetch_source(url: str, session: requests.Session, retries: int,
                 timeout: float, verbose: bool, logger=print,
                 max_bytes: int = MAX_SOURCE_BYTES) -> str:
    """Fetch one bounded public feed; never follow redirects or log full URLs.

    Elapsed-time checks run between chunks; socket read timeout is NOT a
    guaranteed hard wall-clock deadline for an uncooperative peer.
    """
    validate_source_url(url)
    if timeout <= 0 or retries < 0 or max_bytes < 1:
        raise AppError("invalid source fetch limits")
    parsed = urlparse(url)
    headers: Dict[str, str] = {}
    # Never attach GitHub credentials to arbitrary source URLs or raw feeds.
    if GITHUB_TOKEN and parsed.hostname == "api.github.com":
        headers["Authorization"] = "Bearer %s" % GITHUB_TOKEN
    deadline = time.monotonic() + MAX_SOURCE_ELAPSED
    limit = min(max_bytes, MAX_SOURCE_BYTES)
    for attempt in range(retries + 1):
        if time.monotonic() >= deadline:
            raise AppError("source elapsed-time budget exceeded")
        try:
            with session.get(url, headers=headers, timeout=timeout,
                             stream=True, allow_redirects=False) as response:
                code = response.status_code
                if code != 200:
                    if code not in (429, 500, 502, 503, 504) or attempt == retries:
                        raise AppError("source HTTP %d" % code)
                else:
                    chunks = []
                    total = 0
                    for chunk in response.iter_content(65536):
                        if time.monotonic() >= deadline:
                            raise AppError("source elapsed-time budget exceeded")
                        total += len(chunk)
                        if total > limit:
                            raise AppError("source exceeds allowed byte limit")
                        if chunk:
                            chunks.append(chunk)
                    return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
        except requests.RequestException as exc:
            if attempt == retries:
                # requests exception text can include subscription credentials.
                raise AppError("source transport failure (%s)" % type(exc).__name__) from exc
        if verbose:
            logger("[SOURCE RETRY] %s attempt=%d" % (source_label(url), attempt + 1))
        if attempt < retries:
            time.sleep(min(3.0, max(0.0, deadline - time.monotonic())))
    raise AppError("source retry budget exhausted")


def collect_links(sources: Sequence[str], seed_file: str, session: requests.Session,
                  retries: int, timeout: float, verbose: bool, logger=print,
                  source_links: Optional[Dict[str, Set[str]]] = None,
                  telegram_limit: int = 50, telegram_hours: int = 24,
                  protocols: Optional[Set[str]] = None,
                  source_health: Optional[Dict[str, dict]] = None,
                  total_budget_bytes: int = MAX_TOTAL_SOURCE_BYTES) -> Set[str]:
    if len(sources) > MAX_SOURCE_COUNT or total_budget_bytes < 1:
        raise AppError("source count or cumulative download budget exceeds limit")
    links: Set[str] = set()
    remaining = total_budget_bytes
    if seed_file:
        seeded = set(extract_links_from_subscription(read_text_file(seed_file)))
        links.update(seeded)
        if source_links is not None:
            source_links["seed:" + Path(seed_file).name] = seeded
    for index, source in enumerate(sources, 1):
        pilot_id = PILOT_IDS_BY_URL.get(source)
        health = {
            "source_id": pilot_id or hashlib.sha256(source.encode("utf-8")).hexdigest()[:12],
            "tier": "LIGHT" if pilot_id else "EXISTING",
            "status": "pending", "bytes": 0, "raw_candidates": 0,
            "selected_candidates": 0, "fetched_at_utc": None,
            "failure_kind": None,
        }
        if source_links is not None:
            source_links[source] = set()
        if source_health is not None:
            source_health[source] = health
        if remaining < 1:
            health["status"] = "budget_skipped"
            logger("[SOURCE %d/%d] %s: cumulative budget exhausted" %
                   (index, len(sources), source_label(source)))
            continue
        used_bytes = 0
        per_source_cap = min(PILOT_SOURCE_BYTES if pilot_id else MAX_SOURCE_BYTES, remaining)

        def get_text(page_url: str) -> str:
            nonlocal used_bytes
            available = min(per_source_cap - used_bytes, remaining - used_bytes)
            if available <= 0:
                raise AppError("source cumulative byte budget exceeded")
            content = fetch_source(page_url, session, retries, timeout, verbose,
                                   logger, available)
            # Account conservatively for decoded characters; the HTTP stream
            # itself is capped inside fetch_source before UTF-8 decoding.
            size = len(content.encode("utf-8"))
            if size > available:
                raise AppError("source cumulative byte budget exceeded")
            used_bytes += size
            return content

        try:
            if telegram_preview_url(source) is not None:
                found = list(collect_telegram_links(
                    source, get_text, telegram_limit, telegram_hours,
                    logger=logger, protocols=protocols,
                ))
                has_input = bool(found)
            else:
                text = get_text(source)
                has_input = bool(text.strip())
                found = extract_links_from_subscription(text)
            health["raw_candidates"] = len(found)
            if pilot_id and found:
                # Prioritize distinct connection identities, not display remarks.
                unique = {}
                for link in found:
                    try:
                        config = parse_link(link)
                    except AppError:
                        continue
                    unique.setdefault(config.dedup_key, link)
                keys = sorted(unique)
                if len(keys) > PILOT_UNIQUE_LIMIT:
                    health["status"] = "capped"
                    keys = keys[:PILOT_UNIQUE_LIMIT]
                found = [unique[key] for key in keys]
            if health["status"] == "pending":
                health["status"] = "ok" if found else ("invalid" if has_input else "empty")
            health["selected_candidates"] = len(found)
            health["fetched_at_utc"] = datetime.now(timezone.utc).isoformat()
            links.update(found)
            if source_links is not None:
                source_links[source].update(found)
            logger("[SOURCE %d/%d] %s: %d links (%s)" %
                   (index, len(sources), source_label(source), len(found), health["status"]))
        except AppError as exc:
            health["status"] = "failed"
            health["failure_kind"] = str(exc)[:120]
            logger("[SOURCE %d/%d] %s failed: %s" %
                   (index, len(sources), source_label(source), health["failure_kind"]))
        finally:
            health["bytes"] = used_bytes
            remaining -= used_bytes
    return links
