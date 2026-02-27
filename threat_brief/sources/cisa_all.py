from __future__ import annotations

import html as html_mod
import logging
import re
from datetime import datetime, timezone

import subprocess

import feedparser
from bs4 import BeautifulSoup

from threat_brief.models import ThreatEntry

logger = logging.getLogger(__name__)

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
_CVSS_SCORE_PATTERN = re.compile(r"v[34]\s+([\d.]+)")

_BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def fetch_cisa_advisories(url: str, cutoff: datetime) -> list[ThreatEntry]:
    """Parse CISA All Advisories RSS feed for threat intel items."""
    logger.info("Fetching CISA Advisories RSS feed...")
    # CISA uses HTTP/2 which Python's urllib3/requests can't handle.
    # Use curl (which supports HTTP/2 natively) to download the feed.
    try:
        result = subprocess.run(
            [
                "curl", "-s", "-f",
                "--max-time", "30",
                "-H", f"User-Agent: {_BROWSER_UA}",
                url,
            ],
            capture_output=True,
            timeout=35,
        )
        if result.returncode == 22:  # curl -f returns 22 for HTTP 4xx/5xx
            logger.warning(
                "CISA Advisories feed returned an HTTP error (likely 403). "
                "Check if CISA has changed access requirements."
            )
            return []
        if result.returncode != 0:
            logger.error("curl failed with exit code %d", result.returncode)
            return []
        feed = feedparser.parse(result.stdout)
        if feed.bozo and not feed.entries:
            raise ValueError(f"Feed parse error: {feed.bozo_exception}")
    except Exception:
        logger.exception("Failed to fetch CISA Advisories RSS")
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
        link = item.get("link", "")
        raw_desc = item.get("summary", "") or item.get("description", "")

        try:
            entry = _parse_advisory(title, link, dt, raw_desc)
            entries.append(entry)
        except Exception:
            logger.warning("Failed to parse CISA advisory: %s", title, exc_info=True)
            continue

    logger.info("CISA Advisories: found %d entries in window", len(entries))
    return entries


def _parse_advisory(
    title: str, link: str, dt: datetime, raw_desc: str
) -> ThreatEntry:
    """Parse the HTML description of a CISA advisory into a ThreatEntry."""
    decoded = html_mod.unescape(raw_desc)
    soup = BeautifulSoup(decoded, "html.parser")

    # Extract CVEs from entire description
    cves = list(set(_CVE_PATTERN.findall(decoded)))

    # Extract summary
    summary = _extract_summary(soup)

    # Extract CVSS table data
    vendor, equipment, vulns, max_score = _parse_cvss_table(soup)

    # Extract sectors
    sectors = _extract_sectors(soup)

    # Build severity from highest CVSS score
    severity = _score_to_severity(max_score)

    # Build description
    desc_parts = []
    if summary:
        desc_parts.append(summary)
    if vendor or equipment:
        desc_parts.append(f"Vendor: {vendor or 'N/A'}, Equipment: {equipment or 'N/A'}")
    if sectors:
        desc_parts.append(f"Sectors: {sectors}")
    description = " | ".join(desc_parts) if desc_parts else title

    return ThreatEntry(
        title=title,
        source="CISA Advisories",
        date=dt,
        severity=severity,
        cves=cves,
        description=description[:500],
        url=link,
    )


def _extract_summary(soup: BeautifulSoup) -> str:
    """Extract summary text following the <h2>Summary</h2> heading."""
    h2 = soup.find("h2", string=re.compile(r"Summary", re.IGNORECASE))
    if not h2:
        return ""
    # Get the next <p> sibling(s) after the summary heading
    parts = []
    for sibling in h2.find_next_siblings():
        if sibling.name in ("h2", "h3", "div", "hr"):
            break
        if sibling.name == "p":
            text = sibling.get_text(strip=True)
            if text:
                parts.append(text)
    return " ".join(parts)


def _parse_cvss_table(soup: BeautifulSoup) -> tuple[str, str, str, float | None]:
    """Parse the CVSS summary table. Returns (vendor, equipment, vulns, max_score)."""
    table = soup.find("table", class_=re.compile(r"tablesaw"))
    if not table:
        return "", "", "", None

    max_score: float | None = None
    vendors: list[str] = []
    equipments: list[str] = []
    vulns_list: list[str] = []

    for row in table.find_all("tr"):
        cells = row.find_all("td")
        if len(cells) < 4:
            continue

        cvss_text = cells[0].get_text(strip=True)
        vendor = cells[1].get_text(strip=True)
        equipment = cells[2].get_text(strip=True)
        vuln = cells[3].get_text(strip=True)

        # Parse score from "v3 9.4" or "v4 8.1"
        match = _CVSS_SCORE_PATTERN.search(cvss_text)
        if match:
            score = float(match.group(1))
            if max_score is None or score > max_score:
                max_score = score

        if vendor and vendor not in vendors:
            vendors.append(vendor)
        if equipment and equipment not in equipments:
            equipments.append(equipment)
        if vuln and vuln not in vulns_list:
            vulns_list.append(vuln)

    return (
        ", ".join(vendors),
        ", ".join(equipments),
        ", ".join(vulns_list),
        max_score,
    )


def _extract_sectors(soup: BeautifulSoup) -> str:
    """Extract critical infrastructure sectors from the Background section."""
    sector_tag = soup.find("strong", string=re.compile(r"Critical Infrastructure Sectors"))
    if not sector_tag:
        return ""
    # The sector text is in the same <li> as the <strong> tag
    parent = sector_tag.parent
    if parent:
        text = parent.get_text(strip=True)
        # Remove the label prefix
        text = re.sub(
            r"Critical Infrastructure Sectors:\s*", "", text, flags=re.IGNORECASE
        )
        return text.strip()
    return ""


def _score_to_severity(score: float | None) -> str:
    """Map CVSS score to severity string."""
    if score is None:
        return "Medium"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"
