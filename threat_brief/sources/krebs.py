from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

import feedparser

from threat_brief.models import ThreatEntry

logger = logging.getLogger(__name__)

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")


def fetch_krebs(url: str, cutoff: datetime) -> list[ThreatEntry]:
    """Parse Krebs on Security RSS feed for threat intel items."""
    logger.info("Fetching Krebs on Security RSS feed...")
    try:
        feed = feedparser.parse(url)
        if feed.bozo and not feed.entries:
            raise ValueError(f"Feed parse error: {feed.bozo_exception}")
    except Exception:
        logger.exception("Failed to fetch Krebs on Security RSS")
        return []

    entries: list[ThreatEntry] = []
    for item in feed.entries:
        published = item.get("published_parsed") or item.get("updated_parsed")
        if not published:
            continue

        from calendar import timegm

        dt = datetime.fromtimestamp(timegm(published), tz=timezone.utc)
        if dt < cutoff:
            continue

        title = item.get("title", "")
        summary = item.get("summary", "")
        link = item.get("link", "")

        cves = list(set(_CVE_PATTERN.findall(f"{title} {summary}")))
        severity = _estimate_severity(title, summary)

        entries.append(
            ThreatEntry(
                title=title,
                source="Krebs on Security",
                date=dt,
                severity=severity,
                cves=cves,
                description=_clean_html(summary)[:500],
                url=link,
            )
        )

    logger.info("Krebs on Security: found %d entries in window", len(entries))
    return entries


def _estimate_severity(title: str, summary: str) -> str:
    text = f"{title} {summary}".lower()
    critical_keywords = [
        "zero-day", "0-day", "actively exploited", "critical", "rce",
        "remote code execution", "ransomware", "supply chain",
    ]
    high_keywords = [
        "vulnerability", "exploit", "breach", "malware", "apt",
        "backdoor", "patch", "cve-",
    ]
    for kw in critical_keywords:
        if kw in text:
            return "Critical"
    for kw in high_keywords:
        if kw in text:
            return "High"
    return "Medium"


def _clean_html(text: str) -> str:
    """Strip HTML tags from summary text."""
    return re.sub(r"<[^>]+>", "", text).strip()
