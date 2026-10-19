# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Sequence, Set, Tuple
from urllib.parse import urlparse

from vmess_types import ProxyConfig


def source_label(source: str) -> str:
    if source.startswith("seed:"):
        return source
    parsed = urlparse(source)
    # Do not copy subscription passwords, query tokens or fragments to reports.
    host = parsed.hostname or ""
    if ":" in host:
        host = "[" + host + "]"
    if parsed.port:
        host += ":%d" % parsed.port
    label = "%s://%s%s" % (parsed.scheme, host, parsed.path)
    if parsed.query or parsed.username or parsed.password:
        label += " [id:" + hashlib.sha256(source.encode("utf-8")).hexdigest()[:8] + "]"
    return label


def load_recent_results(directory: Path, settings: Mapping[str, object],
                        logger=print, now=None) -> Tuple[Dict[str, dict], str]:
    """Use the latest compatible completed run, at most seven days old.

    Legacy reports need no source tags: match configuration identities, never
    infer the origin of a configuration from its remark.
    """
    current = now or datetime.now(timezone.utc)
    paths = sorted(directory.glob("*_report.json"), reverse=True)
    for path in paths[:20]:
        if not re.fullmatch(r"\d{8}_\d{6}_report.json", path.name):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            metadata = data["metadata"]
            if metadata.get("interrupted") is not False:
                continue
            if any(metadata.get(key, False if key == "allow_insecure_server_cert" else None) != value
                   for key, value in settings.items()):
                continue
            date = datetime.fromisoformat(metadata["generated_at_utc"].replace("Z", "+00:00"))
            if date.tzinfo is None or not current - timedelta(days=7) <= date <= current:
                continue
            history = {}
            for row in data["all_results"]:
                if row.get("error_stage") == "parse":
                    continue
                key, accepted, score = row["key"], row["accepted"], row["score"]
                if (not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key)
                        or type(accepted) is not bool or type(score) is not int or not 0 <= score <= 100):
                    raise ValueError("invalid history result")
                history[key] = {"accepted": accepted, "score": score}
            return history, path.name
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            logger("[SOURCE HISTORY] Ignoring unreadable/invalid report %s (%s)" % (path.name, type(exc).__name__))
    return {}, ""


def prioritize_configs(configs: Sequence[ProxyConfig], source_links: Mapping[str, Set[str]],
                       link_keys: Mapping[str, str], history: Mapping[str, dict], min_matches: int = 5):
    membership: Dict[str, Set[str]] = {}
    for source, links in source_links.items():
        for link in links:
            key = link_keys.get(link)
            if key:
                membership.setdefault(key, set()).add(source)
    rows: List[dict] = []
    for source, links in source_links.items():
        keys = {link_keys[link] for link in links if link in link_keys}
        matches = [history[key] for key in keys if key in history]
        accepted = sum(row["accepted"] for row in matches)
        rate = accepted / len(matches) if len(matches) >= min_matches else None
        rows.append({
            "source": source_label(source), "collected_links": len(links), "unique_configs": len(keys),
            "history_matches": len(matches), "history_accepted": accepted,
            "history_acceptance_rate": rate,
            "minimum_history_matches": min_matches,
            "quality_basis": "matching_current_config_identities" if rate is not None else "unknown",
            "shared_configs": sum(len(membership[key]) > 1 for key in keys),
            "assigned_configs": 0, "tested": 0, "accepted": 0,
            "_source": source,
        })
    # Successful historical sources first, unmeasured sources next, failed-only
    # sources last. Within each quality level, prefer fewer unique configs.
    def source_rank(row):
        group = (3 if not row["unique_configs"] else
                 (1 if row["history_acceptance_rate"] is None else
                  (0 if row["history_accepted"] else 2)))
        return (group, -(row["history_acceptance_rate"] or 0.0), row["unique_configs"], row["source"])
    rows.sort(key=source_rank)
    ranks = {row["_source"]: index for index, row in enumerate(rows)}
    owners = {key: min(feeds, key=lambda source: ranks[source]) for key, feeds in membership.items()}

    def config_rank(config):
        record = history.get(config.dedup_key)
        group = 0 if record and record["accepted"] else (1 if record is None else 2)
        return (ranks.get(owners.get(config.dedup_key), len(rows)), group,
                -record["score"] if record else 0, config.dedup_key)

    ordered = sorted(configs, key=config_rank)
    for config in ordered:
        source = owners.get(config.dedup_key)
        if source in ranks:
            rows[ranks[source]]["assigned_configs"] += 1
    config_sources = {key: [ranks[source] for source in sorted(feeds, key=lambda source: ranks[source])]
                      for key, feeds in membership.items()}
    for row in rows:
        del row["_source"]
    return ordered, rows, config_sources
