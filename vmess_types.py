# -*- coding: utf-8 -*-
from __future__ import annotations

import base64
import hashlib
import json
import re
import statistics
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote

VMESS_RE = re.compile(r"vmess://[^\s\"'<>]+", re.IGNORECASE)


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
    return VmessConfig(
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
    )


def calculate_score(
    probes: Sequence[ProbeResult], insecure_tls: bool
) -> Tuple[int, float, Optional[float]]:
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


def calculate_input_set_sha256(links: Iterable[str]) -> str:
    payload = "\n".join(sorted(set(links))).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
