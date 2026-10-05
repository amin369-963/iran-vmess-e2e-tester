# -*- coding: utf-8 -*-
from __future__ import annotations

import base64
import hashlib
import json
import re
import statistics
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

# Single source of truth for the application version.
APP_VERSION = "3.2.0"

SCHEME_TO_PROTOCOL: Dict[str, str] = {
    "vmess": "vmess",
    "vless": "vless",
    "trojan": "trojan",
    "ss": "shadowsocks",
}
SUPPORTED_PROTOCOLS: Tuple[str, ...] = ("vmess", "vless", "trojan", "shadowsocks")

LINK_RE = re.compile(r"(?:vmess|vless|trojan|ss)://[^\s\"'<>]+", re.IGNORECASE)
VMESS_RE = re.compile(r"vmess://[^\s\"'<>]+", re.IGNORECASE)
LINK_TRAILING_CHARS = ")]}>،,;؛。.'\""

# Shadowsocks ciphers accepted by current Xray releases.
SHADOWSOCKS_METHODS = {
    "aes-128-gcm", "aes-256-gcm",
    "chacha20-poly1305", "chacha20-ietf-poly1305",
    "xchacha20-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none", "plain",
}


class AppError(RuntimeError):
    """Expected user-facing error."""


@dataclass(frozen=True)
class ProxyConfig:
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
    protocol: str = "vmess"
    password: str = ""
    method: str = ""
    flow: str = ""
    encryption: str = ""
    public_key: str = ""
    short_id: str = ""
    spider_x: str = ""

    @property
    def dedup_key(self) -> str:
        values = (
            self.protocol, self.address.lower(), str(self.port), self.user_id,
            str(self.alter_id), self.cipher, self.network, self.transport_security,
            self.sni.lower(), self.host.lower(), self.path, self.service_name,
            self.authority.lower(), self.password, self.method, self.flow,
            self.encryption, self.public_key, self.short_id,
        )
        return hashlib.sha256("|".join(values).encode("utf-8")).hexdigest()


# Backward-compatible name used by older code and tests.
VmessConfig = ProxyConfig


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
    protocol: str = ""
    speed_kbps: float = 0.0
    country: str = ""
    ip: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


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


def _extract_with(pattern: "re.Pattern[str]", text: str) -> List[str]:
    found: List[str] = []
    seen: Set[str] = set()
    for match in pattern.finditer(text or ""):
        link = match.group(0).rstrip(LINK_TRAILING_CHARS)
        if link not in seen:
            seen.add(link)
            found.append(link)
    return found


def extract_vmess_links(text: str) -> List[str]:
    return _extract_with(VMESS_RE, text)


def extract_proxy_links(text: str) -> List[str]:
    """Extract vmess://, vless://, trojan:// and ss:// links."""
    return _extract_with(LINK_RE, text)


def extract_links_from_subscription(text: str) -> List[str]:
    links = extract_proxy_links(text)
    decoded = decode_base64_text(text)
    if decoded and decoded != text:
        seen = set(links)
        for link in extract_proxy_links(decoded):
            if link not in seen:
                seen.add(link)
                links.append(link)
    return links


def link_protocol(link: str) -> str:
    scheme = link.split("://", 1)[0].lower() if "://" in link else ""
    return SCHEME_TO_PROTOCOL.get(scheme, "")


def normalize_network(value: str) -> str:
    mapping = {
        "": "raw", "tcp": "raw", "raw": "raw",
        "ws": "websocket", "websocket": "websocket",
        "grpc": "grpc", "gun": "grpc", "kcp": "mkcp", "mkcp": "mkcp",
        "httpupgrade": "httpupgrade", "http-upgrade": "httpupgrade",
        "xhttp": "xhttp", "splithttp": "xhttp",
    }
    key = value.strip().lower()
    if key in {"http", "h2", "h3"}:
        raise AppError("unsupported transport: %s (removed from Xray; migrated to XHTTP)" % key)
    if key not in mapping:
        raise AppError("unsupported transport: %s" % (key or "<empty>"))
    return mapping[key]


def normalize_security(value: str, default: str = "none") -> str:
    key = value.strip().lower()
    if not key:
        return default
    if key in {"tls", "xtls"}:
        return "tls"
    if key == "reality":
        return "reality"
    if key in {"none", "false", "0", "off"}:
        return "none"
    raise AppError("unsupported security: %s" % key)


def parse_alpn(value: object) -> Tuple[str, ...]:
    if isinstance(value, list):
        raw_items = [clean_text(item) for item in value]
    else:
        raw = clean_text(value)
        raw_items = re.split(r"[,|]", raw) if raw else []
    return tuple(item.strip() for item in raw_items if item.strip())


def parse_vmess_link(link: str) -> ProxyConfig:
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
    return ProxyConfig(
        raw=link,
        address=address,
        port=port,
        user_id=user_id,
        alter_id=alter_id,
        cipher=(clean_text(data.get("scy")) or "auto").lower(),
        network=normalize_network(clean_text(data.get("net"))),
        transport_security=security,
        sni=clean_text(data.get("sni")) or clean_text(data.get("host")),
        host=clean_text(data.get("host")),
        path=clean_text(data.get("path")) or "/",
        service_name=clean_text(data.get("serviceName")) or clean_text(data.get("path")),
        authority=clean_text(data.get("authority")) or clean_text(data.get("host")),
        alpn=parse_alpn(data.get("alpn")),
        fingerprint=clean_text(data.get("fp")) or "chrome",
        allow_insecure=parse_bool(data.get("allowInsecure")),
        remark=clean_text(data.get("ps")),
        header_type=clean_text(data.get("type")) or "none",
        protocol="vmess",
    )


def _split_host_port(netloc: str) -> Tuple[str, int]:
    """Parse ``host:port`` (IPv6 in brackets allowed)."""
    try:
        parts = urlsplit("//" + netloc.strip().rstrip("/"))
        host = parts.hostname or ""
        port = parts.port
    except ValueError as exc:
        raise AppError("invalid server address or port") from exc
    if not host or any(ch.isspace() for ch in host):
        raise AppError("missing or invalid server address")
    if port is None or not 1 <= port <= 65535:
        raise AppError("missing or invalid server port")
    return host, port


def _parse_uri_link(link: str, protocol: str) -> ProxyConfig:
    """Parse the shared URI format used by vless:// and trojan:// links."""
    try:
        parts = urlsplit(link.strip())
    except ValueError as exc:
        raise AppError("invalid %s link" % protocol) from exc
    if "@" not in parts.netloc:
        raise AppError("missing %s credentials" % protocol)
    userinfo, hostport = parts.netloc.rsplit("@", 1)
    credential = unquote(userinfo).strip()
    if not credential:
        raise AppError("missing %s credentials" % protocol)
    address, port = _split_host_port(hostport)

    query = {key.lower(): values for key, values in parse_qs(parts.query, keep_blank_values=True).items()}

    def param(*names: str) -> str:
        for name in names:
            value = clean_text(query.get(name.lower()))
            if value:
                return value
        return ""

    default_security = "tls" if protocol == "trojan" else "none"
    security = normalize_security(param("security"), default_security)
    network = normalize_network(param("type", "net"))
    host = param("host")
    path = param("path")
    sni = param("sni", "peer", "servername") or host
    public_key = param("pbk", "publickey", "password")
    if security == "reality" and not public_key:
        raise AppError("REALITY link is missing public key (pbk)")

    return ProxyConfig(
        raw=link,
        address=address,
        port=port,
        user_id=credential if protocol == "vless" else "",
        alter_id=0,
        cipher="",
        network=network,
        transport_security=security,
        sni=sni,
        host=host,
        path=path or "/",
        service_name=param("servicename") or (path if network == "grpc" else ""),
        authority=param("authority") or host,
        alpn=parse_alpn(param("alpn")),
        fingerprint=param("fp", "fingerprint") or "chrome",
        allow_insecure=parse_bool(param("allowinsecure", "insecure")),
        remark=unquote(parts.fragment).strip(),
        header_type=param("headertype") or "none",
        protocol=protocol,
        password=credential if protocol == "trojan" else "",
        flow=param("flow") if protocol == "vless" else "",
        encryption=(param("encryption") or "none") if protocol == "vless" else "",
        public_key=public_key if security == "reality" else "",
        short_id=param("sid", "shortid") if security == "reality" else "",
        spider_x=param("spx", "spiderx") if security == "reality" else "",
    )


def parse_vless_link(link: str) -> ProxyConfig:
    if not link.lower().startswith("vless://"):
        raise AppError("not a VLESS link")
    return _parse_uri_link(link, "vless")


def parse_trojan_link(link: str) -> ProxyConfig:
    if not link.lower().startswith("trojan://"):
        raise AppError("not a Trojan link")
    return _parse_uri_link(link, "trojan")


def parse_shadowsocks_link(link: str) -> ProxyConfig:
    """Parse SIP002 (``ss://userinfo@host:port#tag``) and legacy base64 links."""
    if not link.lower().startswith("ss://"):
        raise AppError("not a Shadowsocks link")
    body = link.strip()[5:]
    body, _, fragment = body.partition("#")
    body, _, query = body.partition("?")
    if query:
        options = parse_qs(query)
        if clean_text(options.get("plugin")):
            raise AppError("Shadowsocks plugins are not supported")
    body = body.rstrip("/")

    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        userinfo = unquote(userinfo)
        if ":" not in userinfo:
            userinfo = decode_base64_text(userinfo)
    else:
        decoded = decode_base64_text(unquote(body))
        if "@" not in decoded:
            raise AppError("invalid Shadowsocks payload")
        userinfo, hostport = decoded.rsplit("@", 1)

    if ":" not in userinfo:
        raise AppError("invalid Shadowsocks credentials")
    method, password = userinfo.split(":", 1)
    method = method.strip().lower()
    if method not in SHADOWSOCKS_METHODS:
        raise AppError("unsupported Shadowsocks method: %s" % (method or "<empty>"))
    if not password and method not in {"none", "plain"}:
        raise AppError("missing Shadowsocks password")
    address, port = _split_host_port(hostport)

    return ProxyConfig(
        raw=link,
        address=address,
        port=port,
        user_id="",
        alter_id=0,
        cipher="",
        network="raw",
        transport_security="none",
        sni="",
        host="",
        path="/",
        service_name="",
        authority="",
        alpn=(),
        fingerprint="",
        allow_insecure=False,
        remark=unquote(fragment).strip(),
        header_type="none",
        protocol="shadowsocks",
        password=password,
        method=method,
    )


def parse_link(link: str) -> ProxyConfig:
    """Parse any supported proxy link."""
    if not isinstance(link, str):
        raise AppError("link must be text")
    protocol = link_protocol(link)
    if protocol == "vmess":
        return parse_vmess_link(link)
    if protocol == "vless":
        return parse_vless_link(link)
    if protocol == "trojan":
        return parse_trojan_link(link)
    if protocol == "shadowsocks":
        return parse_shadowsocks_link(link)
    raise AppError("unsupported link scheme")


def calculate_score(
    probes: Sequence[ProbeResult],
    insecure_tls: bool,
    speed_kbps: float = 0.0,
    blocked_sites_passed: int = 0,
    uptime_ratio: Optional[float] = None,
) -> Tuple[int, float, Optional[float]]:
    if not probes:
        return 0, 0.0, None
    successes = [item for item in probes if item.success and item.elapsed_ms is not None]
    rate = len(successes) / float(len(probes))
    if not successes:
        return 0, rate, None
    latencies = [float(item.elapsed_ms) for item in successes if item.elapsed_ms is not None]
    median = statistics.median(latencies)

    # Base probe success score: up to 40
    base_points = int(round(rate * 40))

    # Latency points: up to 20
    if median <= 400:
        latency_points = 20
    elif median <= 800:
        latency_points = 16
    elif median <= 1500:
        latency_points = 12
    elif median <= 3000:
        latency_points = 7
    else:
        latency_points = 2

    # Stability points: up to 10
    if len(latencies) <= 1:
        stability_points = 10
    else:
        deviation = statistics.pstdev(latencies)
        stability_points = 10 if deviation <= 200 else 6 if deviation <= 600 else 2

    # Download Speed points: up to 20
    # speed_kbps: 0 -> 0, 250 KB/s (~2 Mbps) -> 5, 1000 KB/s (~8 Mbps) -> 12, 3000+ KB/s -> 20
    if speed_kbps >= 3000:
        speed_points = 20
    elif speed_kbps >= 1500:
        speed_points = 15
    elif speed_kbps >= 600:
        speed_points = 10
    elif speed_kbps >= 150:
        speed_points = 5
    elif speed_kbps > 0:
        speed_points = 2
    else:
        speed_points = 0

    # Blocked sites verification (e.g. YouTube): up to 10
    target_points = min(10, blocked_sites_passed * 5)

    # Historical uptime bonus: up to 5
    uptime_points = int(round(uptime_ratio * 5)) if uptime_ratio is not None else 0

    total_score = base_points + latency_points + stability_points + speed_points + target_points + uptime_points
    if insecure_tls:
        total_score -= 10

    score = max(0, min(100, total_score))
    return score, rate, float(median)


def calculate_input_set_sha256(links: Iterable[str]) -> str:
    payload = "\n".join(sorted(set(links))).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
