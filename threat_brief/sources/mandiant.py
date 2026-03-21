"""Mandiant Threat Intelligence source — Google/Mandiant research blog RSS feed."""
from __future__ import annotations

import logging
import re
from calendar import timegm
from datetime import datetime, timezone

import feedparser
import requests

from threat_brief.models import ThreatEntry

logger = logging.getLogger(__name__)

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")

_BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def fetch_mandiant(url: str, cutoff: datetime) -> list[ThreatEntry]:
    """Parse Mandiant Threat Intelligence RSS feed for items within the time window."""
    logger.info("Fetching Mandiant Threat Intelligence RSS feed...")
    try:
        resp = requests.get(url, headers={"User-Agent": _BROWSER_UA}, timeout=30)
        resp.raise_for_status()
        feed = feedparser.parse(resp.content)
        if feed.bozo and not feed.entries:
            raise ValueError(f"Feed parse error: {feed.bozo_exception}")
    except Exception:
        logger.exception("Failed to fetch Mandiant RSS")
        return []

    entries: list[ThreatEntry] = []
    for item in feed.entries:
        published = item.get("published_parsed") or item.get("updated_parsed")
        if not published:
            continue

        dt = datetime.fromtimestamp(timegm(published), tz=timezone.utc)
        if dt < cutoff:
            continue

        title = _clean_html(item.get("title", ""))
        link = item.get("link", "")

        # Prefer full content over summary when available
        content_list = item.get("content", [])
        raw_content = content_list[0].get("value", "") if content_list else ""
        raw = raw_content or item.get("summary", "")

        cves = list(set(_CVE_PATTERN.findall(f"{title} {raw}")))
        description = _clean_html(raw)[:700]

        entries.append(
            ThreatEntry(
                title=title,
                source="Mandiant",
                date=dt,
                severity="Medium",
                cves=cves,
                description=description,
                url=link,
            )
        )

    logger.info("Mandiant: found %d entries in window", len(entries))
    return entries


def _clean_html(text: str) -> str:
    """Strip HTML tags from text."""
    return re.sub(r"<[^>]+>", "", text).strip()
