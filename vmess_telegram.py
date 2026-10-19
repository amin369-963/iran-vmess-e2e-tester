# -*- coding: utf-8 -*-
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse

from vmess_types import AppError, extract_proxy_links, parse_link

MAX_TELEGRAM_PAGES = 10


def telegram_preview_url(source: str) -> Optional[str]:
    parsed = urlparse(source)
    if (parsed.hostname or "").lower() not in {"t.me", "www.t.me", "telegram.me", "www.telegram.me"}:
        return None
    parts = parsed.path.strip("/").split("/")
    if parts and parts[0] == "s":
        parts = parts[1:]
    if (parsed.scheme not in {"http", "https"} or parsed.username or parsed.password
            or len(parts) != 1 or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,31}", parts[0])):
        raise AppError("Telegram source must be a public channel URL: https://t.me/s/channel")
    return "https://t.me/s/" + parts[0].lower()


class TelegramPreviewParser(HTMLParser):
    """Read post text and UTC dates, excluding channel bios and forwarded headers."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.posts: List[Tuple[int, datetime, str]] = []
        self.depth = 0
        self.message_depth: Optional[int] = None
        self.text_depth: Optional[int] = None
        self.message_id = 0
        self.date: Optional[datetime] = None
        self.text: List[str] = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        classes = (attributes.get("class") or "").split()
        if tag == "div":
            self.depth += 1
            if "tgme_widget_message" in classes:
                post = attributes.get("data-post") or ""
                self.message_depth = self.depth
                self.message_id = int(post.rsplit("/", 1)[-1]) if post.rsplit("/", 1)[-1].isdigit() else 0
                self.date = None
                self.text = []
                self.text_depth = None
            if self.message_depth is not None and "tgme_widget_message_text" in classes:
                self.text_depth = self.depth
        if self.message_depth is None:
            return
        if tag == "time" and attributes.get("datetime"):
            try:
                date = datetime.fromisoformat(attributes["datetime"].replace("Z", "+00:00"))
                if date.tzinfo is not None:
                    self.date = date.astimezone(timezone.utc)
            except ValueError:
                self.date = None
        if self.text_depth is not None:
            if tag == "br":
                self.text.append("\n")
            elif tag == "a":
                href = attributes.get("href") or ""
                if href.lower().startswith(("vmess://", "vless://", "trojan://", "ss://")):
                    self.text.extend(["\n", href, "\n"])

    def handle_data(self, data):
        if self.text_depth is not None:
            self.text.append(data)

    def handle_endtag(self, tag):
        if tag != "div":
            return
        if self.text_depth == self.depth:
            self.text_depth = None
        if self.message_depth == self.depth:
            if self.date is not None and self.message_id:
                self.posts.append((self.message_id, self.date, "".join(self.text)))
            self.message_depth = None
        self.depth = max(0, self.depth - 1)


def collect_telegram_links(source: str, fetch_page, limit: int = 50,
                           hours: int = 24, now: Optional[datetime] = None,
                           logger=print, protocols: Optional[Set[str]] = None) -> List[str]:
    preview = telegram_preview_url(source)
    if preview is None:
        raise AppError("not a Telegram channel URL")
    if not 1 <= limit <= 500 or not 1 <= hours <= 168:
        raise AppError("telegram-limit must be 1..500 and telegram-hours must be 1..168")
    current = now or datetime.now(timezone.utc)
    cutoff = current - timedelta(hours=hours)
    links: List[str] = []
    identities = set()
    seen_posts = set()
    before = None
    for page in range(MAX_TELEGRAM_PAGES):
        parser = TelegramPreviewParser()
        parser.feed(fetch_page(preview + ("?before=%d" % before if before is not None else "")))
        parser.close()
        if not parser.posts:
            if page == 0:
                raise AppError("Telegram public preview has no readable dated posts; channel may be restricted or unavailable")
            break
        posts = [post for post in parser.posts if post[0] not in seen_posts]
        if not posts:
            break
        for message_id, date, text in sorted(posts, key=lambda post: (post[1], post[0]), reverse=True):
            seen_posts.add(message_id)
            if not cutoff <= date <= current:
                continue
            for link in extract_proxy_links(text):
                try:
                    config = parse_link(link)
                    if protocols is not None and config.protocol not in protocols:
                        continue
                    key = config.dedup_key
                except AppError:
                    continue
                if key not in identities:
                    identities.add(key)
                    links.append(link)
                    if len(links) >= limit:
                        return links
        if min(post[1] for post in posts) < cutoff:
            break
        oldest_id = min(post[0] for post in posts)
        if before is not None and oldest_id >= before:
            break
        before = oldest_id
    else:
        logger("[TELEGRAM] Reached the %d-page collection limit for %s" % (MAX_TELEGRAM_PAGES, preview))
    return links
