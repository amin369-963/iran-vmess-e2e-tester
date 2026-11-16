# -*- coding: utf-8 -*-
"""Public-feed intake smoke, manual/PR only: never test or publish proxies."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vmess_sources import PILOT_SOURCES, build_source_session, collect_links
from vmess_types import AppError, parse_link


def main() -> int:
    urls = [spec["url"] for spec in PILOT_SOURCES.values()]
    health = {}
    origins = {}
    session = build_source_session("")
    try:
        links = collect_links(
            urls, "", session, retries=1, timeout=12.0, verbose=False,
            logger=lambda _msg: None, source_links=origins,
            source_health=health, total_budget_bytes=8 * 1024 * 1024,
        )
    finally:
        session.close()
    identities = set()
    for link in links:
        try:
            identities.add(parse_link(link).dedup_key)
        except AppError:
            continue
    rows = [
        {
            "pilot": health[url]["pilot_id"],
            "status": health[url]["status"],
            "bytes": health[url]["bytes"],
            "raw_candidates": health[url]["raw_candidates"],
            "selected_candidates": health[url]["selected_candidates"],
            "unique_parsed": len({parse_link(link).dedup_key for link in origins[url]}),
        }
        for url in urls
    ]
    # Never print raw links, source response bodies, or account credentials.
    print(json.dumps({"pilot_sources": rows, "combined_unique": len(identities)},
                     ensure_ascii=True, sort_keys=True))
    if any(row["status"] not in ("ok", "capped") for row in rows) or not identities:
        print("Pilot intake smoke: FAIL (no verified proxy reachability claimed)")
        return 1
    print("Pilot intake smoke: PASS (collection only; HTTPS through proxy NOT tested)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
