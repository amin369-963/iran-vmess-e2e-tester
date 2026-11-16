# -*- coding: utf-8 -*-
"""Private, offline subscription preview: no network, uploads or publication."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from vmess_types import IDENTITY_VERSION, AppError, ProbeResult, parse_link
from vmess_xray import _primary_probes_verified, build_probe_plan

PLAIN_NAME = "configs.txt"
BASE64_NAME = "configs_base64.txt"
STATUS_NAME = "status.json"
EXPECTED_FILES = {PLAIN_NAME, BASE64_NAME, STATUS_NAME}
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_PREVIEW_ITEMS = 200
MAX_LINK_CHARS = 16384


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise AppError("missing or invalid %s" % field)
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AppError("invalid %s" % field) from exc
    if date.tzinfo is None:
        raise AppError("%s must include a UTC offset" % field)
    return date.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _load_report(path: Path) -> Tuple[dict, str]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_REPORT_BYTES:
            raise AppError("report is missing or exceeds the safe size limit")
        data = path.read_bytes()
        if len(data) > MAX_REPORT_BYTES:
            raise AppError("report exceeds the safe size limit")
        payload = json.loads(data.decode("utf-8-sig"))
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise AppError("cannot read a valid UTF-8 JSON report") from exc
    if not isinstance(payload, dict):
        raise AppError("report root must be a JSON object")
    return payload, _sha256(data)


def _accepted_lines(payload: dict, now: datetime, ttl_hours: int,
                    max_items: int) -> Tuple[List[str], dict]:
    if not isinstance(ttl_hours, int) or not 1 <= ttl_hours <= 72:
        raise AppError("ttl-hours must be between 1 and 72")
    if not isinstance(max_items, int) or not 1 <= max_items <= MAX_PREVIEW_ITEMS:
        raise AppError("max-items must be between 1 and %d" % MAX_PREVIEW_ITEMS)

    metadata = payload.get("metadata")
    accepted = payload.get("accepted")
    all_results = payload.get("all_results")
    if not isinstance(metadata, dict) or not isinstance(accepted, list) or not isinstance(all_results, list):
        raise AppError("report lacks expected metadata/result arrays")
    if type(metadata.get("identity_version")) is not int or metadata["identity_version"] != IDENTITY_VERSION:
        raise AppError("report has missing or incompatible connection identity version")
    if metadata.get("interrupted") is not False or metadata.get("not_tested_count") != 0:
        raise AppError("partial or interrupted runs cannot produce a subscription preview")

    completed = _utc(metadata.get("testing_completed_at_utc"), "testing_completed_at_utc")
    started = _utc(metadata.get("generated_at_utc"), "generated_at_utc")
    if completed < started or completed > now + timedelta(minutes=5):
        raise AppError("report completion time is inconsistent or in the future")
    expires = completed + timedelta(hours=ttl_hours)
    if now >= expires:
        raise AppError("report is stale: the requested subscription TTL has expired")

    urls = metadata.get("test_urls")
    attempts = metadata.get("attempts")
    if not isinstance(urls, list) or not all(isinstance(item, str) for item in urls):
        raise AppError("report has invalid test URL metadata")
    if type(attempts) is not int or attempts < 1 or attempts > 10:
        raise AppError("report has invalid attempt metadata")
    plan = build_probe_plan(urls, attempts)
    if len(plan) < 4 or len(set(plan)) < 2:
        raise AppError("report cannot demonstrate two-endpoint E2E verification")

    results_by_key: Dict[str, dict] = {}
    tested = 0
    verified_total = 0
    for result in all_results:
        if not isinstance(result, dict):
            raise AppError("malformed result record")
        if result.get("error_stage") == "parse":
            continue
        tested += 1
        key = result.get("key")
        if not isinstance(key, str) or len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
            raise AppError("invalid result identity")
        if key in results_by_key:
            raise AppError("duplicated tested configuration identity")
        results_by_key[key] = result
        if result.get("accepted") is True:
            verified_total += 1

    if (type(payload.get("tested_count")) is not int or payload["tested_count"] != tested
            or type(metadata.get("tested_count")) is not int or metadata["tested_count"] != tested
            or type(metadata.get("accepted_total")) is not int or metadata["accepted_total"] != verified_total
            or type(payload.get("accepted_count")) is not int or payload["accepted_count"] != len(accepted)
            or type(metadata.get("accepted_exported")) is not int
            or metadata["accepted_exported"] != len(accepted)):
        raise AppError("report result counts are inconsistent")
    if not accepted or len(accepted) > max_items or len(accepted) > verified_total:
        raise AppError("no eligible accepted configurations or preview exceeds max-items")

    used = set()
    lines: List[str] = []
    for row in accepted:
        if not isinstance(row, dict) or row.get("accepted") is not True:
            raise AppError("export contains an unverified result")
        link = row.get("link")
        key = row.get("key")
        if (not isinstance(link, str) or not 0 < len(link) <= MAX_LINK_CHARS
                or any(c in link for c in "\r\n\x00")):
            raise AppError("invalid proxy URI in export")
        try:
            parsed = parse_link(link)
        except (AppError, TypeError, ValueError) as exc:
            raise AppError("unparseable proxy URI in export") from exc
        if key != parsed.dedup_key or key in used or results_by_key.get(key) != row:
            raise AppError("exported configuration does not match unique tested evidence")
        probes = row.get("probes")
        if not isinstance(probes, list) or len(probes) != len(plan):
            raise AppError("accepted configuration has incomplete primary HTTPS evidence")
        observations: List[ProbeResult] = []
        for pos, entry in enumerate(probes):
            if not isinstance(entry, dict) or entry.get("url") != plan[pos]:
                raise AppError("HTTPS probe plan mismatch")
            try:
                observations.append(ProbeResult(**entry))
            except (TypeError, ValueError) as exc:
                raise AppError("invalid HTTPS probe result") from exc
        if not _primary_probes_verified(observations, plan):
            raise AppError("accepted configuration lacks sufficient HTTPS 204 evidence")
        used.add(key)
        lines.append(link)

    return lines, {
        "schema_version": 1,
        "distribution": "private-local-preview",
        "published": False,
        "redistribution_authorized": False,
        "vantage_verified": False,
        "vantage_label_sha256": _sha256(str(metadata.get("network_name", "unknown")).encode("utf-8"))[:16],
        "run_identity_version": IDENTITY_VERSION,
        "test_started_at_utc": _iso(started),
        "test_completed_at_utc": _iso(completed),
        "expires_at_utc": _iso(expires),
        "preview_created_at_utc": _iso(now),
        "ttl_hours": ttl_hours,
        "sample_requested": metadata.get("sample_requested", 0),
        "tested_count": tested,
        "e2e_verified_count": verified_total,
        "exported_count": len(lines),
        "verification": "HTTPS 204 empty body; >=3/4 and >=2 distinct endpoints",
        "files": {},
    }


def build_private_preview(report: Path, output_dir: Path, ttl_hours: int = 24,
                          max_items: int = 100,
                          now: Optional[datetime] = None) -> dict:
    """Create a new private directory, never overwrite any existing output."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    payload, source_sha = _load_report(report)
    lines, status = _accepted_lines(payload, current, ttl_hours, max_items)
    plain = ("\n".join(lines) + "\n").encode("utf-8")
    encoded = (base64.b64encode(plain).decode("ascii") + "\n").encode("ascii")
    status["source_report_sha256"] = source_sha
    status["files"] = {
        PLAIN_NAME: {"sha256": _sha256(plain), "bytes": len(plain)},
        BASE64_NAME: {"sha256": _sha256(encoded), "bytes": len(encoded)},
    }

    # Parent/output are locally owned; no public/scheduled deployment exists.
    target = output_dir.expanduser().absolute()
    # Prevent accidental Git staging of subscription credentials in the repo.
    repository = Path(__file__).resolve().parent
    resolved_target = target.resolve(strict=False)
    if resolved_target.is_relative_to(repository) and not resolved_target.is_relative_to(
            repository / "results"):
        raise AppError("private previews inside this repository must be under ignored results/")
    if target.exists() or target.is_symlink():
        raise AppError("preview output already exists; refusing to overwrite")
    target.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        target.mkdir(mode=0o700)
        created = True
        for name, data in ((PLAIN_NAME, plain), (BASE64_NAME, encoded)):
            path = target / name
            with os.fdopen(os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        # A directory with no status.json is an incomplete preview.
        manifest = (json.dumps(status, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("utf-8")
        path = target / STATUS_NAME
        with os.fdopen(os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
            handle.write(manifest)
            handle.flush()
            os.fsync(handle.fileno())
    except (OSError, ValueError, TypeError) as exc:
        if created:
            shutil.rmtree(str(target), ignore_errors=True)
        raise AppError("failed to create private subscription preview") from exc
    return status


def validate_private_preview(directory: Path,
                             now: Optional[datetime] = None) -> dict:
    """Validate local files + manifest, without external requests or credentials."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    folder = directory.expanduser()
    if not folder.is_dir() or folder.is_symlink() or {
        item.name for item in folder.iterdir()
    } != EXPECTED_FILES:
        raise AppError("preview must contain exactly three regular files")
    blobs: Dict[str, bytes] = {}
    for name in EXPECTED_FILES:
        path = folder / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_REPORT_BYTES:
            raise AppError("preview contains an unsafe or oversized file")
        blobs[name] = path.read_bytes()
    try:
        status = json.loads(blobs[STATUS_NAME].decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise AppError("invalid private preview manifest") from exc
    if (not isinstance(status, dict) or type(status.get("schema_version")) is not int
            or status["schema_version"] != 1 or status.get("distribution") != "private-local-preview"
            or status.get("published") is not False
            or status.get("redistribution_authorized") is not False
            or status.get("vantage_verified") is not False):
        raise AppError("preview metadata does not match private-only contract")
    completed = _utc(status.get("test_completed_at_utc"), "test_completed_at_utc")
    expiry = _utc(status.get("expires_at_utc"), "expires_at_utc")
    ttl = status.get("ttl_hours")
    if type(ttl) is not int or not 1 <= ttl <= 72:
        raise AppError("invalid preview TTL")
    if (expiry != completed + timedelta(hours=ttl)
            or current >= expiry or completed > current + timedelta(minutes=5)):
        raise AppError("preview is expired or has inconsistent timestamps")
    descriptors = status.get("files")
    if not isinstance(descriptors, dict) or set(descriptors) != {PLAIN_NAME, BASE64_NAME}:
        raise AppError("preview manifest file index is invalid")
    for name in (PLAIN_NAME, BASE64_NAME):
        entry = descriptors[name]
        if (not isinstance(entry, dict) or set(entry) != {"sha256", "bytes"}
                or entry.get("sha256") != _sha256(blobs[name])
                or entry.get("bytes") != len(blobs[name])):
            raise AppError("subscription checksum or size does not match manifest")

    try:
        plain = blobs[PLAIN_NAME].decode("utf-8")
        b64 = blobs[BASE64_NAME].decode("ascii")
        if not b64.endswith("\n") or base64.b64encode(blobs[PLAIN_NAME]).decode("ascii") != b64[:-1]:
            raise AppError("base64 subscription does not match plain subscription")
        if not plain.endswith("\n") or "\r" in plain:
            raise AppError("plain subscription is not canonical LF text")
        lines = plain[:-1].split("\n")
        keys = []
        for line in lines:
            if not line or len(line) > MAX_LINK_CHARS:
                raise AppError("invalid subscription entry")
            keys.append(parse_link(line).dedup_key)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise AppError("cannot decode valid subscription files") from exc
    if (len(keys) != len(set(keys)) or not keys
            or type(status.get("exported_count")) is not int
            or status["exported_count"] != len(keys)
            or len(keys) > MAX_PREVIEW_ITEMS):
        raise AppError("manifest entry count or uniqueness is invalid")
    return status


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Private subscription preview; NEVER publishes or uploads.")
    commands = parser.add_subparsers(dest="action", required=True)
    build = commands.add_parser("build", help="Create a NEW private directory from a completed JSON report")
    build.add_argument("--report", type=Path, required=True)
    build.add_argument("--output-dir", type=Path, required=True)
    build.add_argument("--ttl-hours", type=int, default=24)
    build.add_argument("--max-items", type=int, default=100)
    verify = commands.add_parser("validate", help="Check hashes, parity and expiry of an existing preview")
    verify.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "build":
            status = build_private_preview(args.report, args.output_dir,
                                           args.ttl_hours, args.max_items)
            validate_private_preview(args.output_dir)
        else:
            status = validate_private_preview(args.directory)
        print("PRIVATE PREVIEW VALID; entries=%d; expiry=%s; published=false" % (
            status["exported_count"], status["expires_at_utc"]))
        return 0
    except (AppError, OSError) as exc:
        print("Private preview rejected (%s)" % type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
