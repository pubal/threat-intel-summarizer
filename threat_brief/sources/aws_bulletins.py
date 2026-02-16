from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup

from threat_brief.models import ThreatEntry

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")


def fetch_aws_bulletins(url: str, cutoff: datetime) -> list[ThreatEntry]:
    """Parse AWS Security Bulletins page for recent entries."""
    logger.info("Fetching AWS Security Bulletins...")
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
    except Exception:
        logger.exception("Failed to fetch AWS Security Bulletins")
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    entries: list[ThreatEntry] = []

    # AWS bulletins page uses a table or list of bulletins
    # The structure may vary; try common patterns
    for item in soup.select("div.aws-text-box, div.lb-txt-normal, tr"):
        text = item.get_text(separator=" ", strip=True)
        if not text or len(text) < 30:
            continue

        # Try to find a date in the text
        date = _extract_date(text)
        if date is None or date < cutoff:
            continue

        # Extract link
        link_tag = item.find("a", href=True)
        link = ""
        title = text[:120]
        if link_tag:
            href = link_tag.get("href", "")
            if href.startswith("/"):
                link = f"https://aws.amazon.com{href}"
            elif href.startswith("http"):
                link = href
            title = link_tag.get_text(strip=True) or title

        cves = CVE_PATTERN.findall(text)

        entries.append(
            ThreatEntry(
                title=title,
                source="AWS Security Bulletin",
                date=date,
                severity="High",
                cves=list(set(cves)),
                description=text[:500],
                url=link or url,
            )
        )

    logger.info("AWS Bulletins: found %d entries in window", len(entries))
    return entries


def _extract_date(text: str) -> datetime | None:
    """Try to extract a date from bulletin text."""
    patterns = [
        r"(\w+ \d{1,2},?\s*\d{4})",  # January 15, 2025
        r"(\d{4}-\d{2}-\d{2})",  # 2025-01-15
        r"(\d{1,2}/\d{1,2}/\d{4})",  # 01/15/2025
    ]
    for pat in patterns:
        match = re.search(pat, text)
        if match:
            date_str = match.group(1)
            for fmt in ("%B %d, %Y", "%B %d %Y", "%Y-%m-%d", "%m/%d/%Y"):
                try:
                    return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
    return None
