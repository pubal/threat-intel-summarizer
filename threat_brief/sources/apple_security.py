"""Apple Security Updates source — scrapes support.apple.com/en-us/100100."""
from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup

from threat_brief.models import ThreatEntry

logger = logging.getLogger(__name__)

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
_EXPLOITED_PATTERN = re.compile(
    r"Apple is aware of a report that this issue may have been exploited",
    re.IGNORECASE,
)

_BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
_BASE_URL = "https://support.apple.com"
_DATE_FMT = "%d %b %Y"  # "17 Mar 2026"
_NO_CVE_TEXT = "This update has no published CVE entries."

# h3 headings on Apple detail pages that are not component names
_SKIP_HEADINGS = frozenset(
    {
        "About security updates",
        "Additional recognition",
        "Additional information",
        "CVE",
        "References",
        "Note",
    }
)


def fetch_apple_security(
    url: str,
    cutoff: datetime,
    source_cfg: dict | None = None,
) -> list[ThreatEntry]:
    """Scrape Apple Security Updates for releases within the time window."""
    cfg = source_cfg or {}
    fetch_details: bool = cfg.get("fetch_details", True)
    group_by_date: bool = cfg.get("group_by_date", True)

    logger.info("Fetching Apple Security Updates...")
    headers = {"User-Agent": _BROWSER_UA}

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
    except Exception:
        logger.exception("Failed to fetch Apple Security Updates page")
        return []

    soup = BeautifulSoup(resp.content, "html.parser")
    table = soup.find("table")
    if not table:
        logger.warning("Apple Security Updates: no table found on page")
        return []

    releases: list[dict] = []
    for row in table.find_all("tr")[1:]:  # skip header row
        cells = row.find_all("td")
        if len(cells) < 3:
            continue

        name_cell = cells[0]
        available_for = cells[1].get_text(strip=True)
        date_str = cells[2].get_text(strip=True)

        if not date_str:
            continue

        try:
            # Apple only provides a date, not a time. Use end-of-day so that
            # releases aren't excluded by an intraday cutoff boundary (e.g. a
            # release dated "24 Mar" would be midnight UTC, which falls outside
            # a 48h window run at 9 AM on March 26).
            release_date = datetime.strptime(date_str, _DATE_FMT).replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
        except ValueError:
            logger.debug("Apple: could not parse date %r", date_str)
            continue

        if release_date < cutoff:
            continue

        link_tag = name_cell.find("a")

        if not link_tag:
            # No detail page — informational-only (e.g. "no published CVE entries")
            name = name_cell.get_text(strip=True).replace(_NO_CVE_TEXT, "").strip()
            releases.append(
                {
                    "name": name,
                    "url": url,
                    "available_for": available_for,
                    "date": release_date,
                    "has_detail": False,
                    "cves": [],
                    "actively_exploited": False,
                    "components": [],
                    "impacts": [],
                }
            )
            continue

        # Use link text only — avoids picking up inline "no CVE entries" text
        # that some cells append after the <a> tag.
        name = link_tag.get_text(strip=True).replace(_NO_CVE_TEXT, "").strip()
        detail_path = link_tag.get("href", "")
        detail_url = (
            _BASE_URL + detail_path
            if detail_path.startswith("/")
            else detail_path
        )
        releases.append(
            {
                "name": name,
                "url": detail_url,
                "available_for": available_for,
                "date": release_date,
                "has_detail": True,
                "cves": [],
                "actively_exploited": False,
                "components": [],
                "impacts": [],
            }
        )

    logger.info("Apple Security Updates: %d releases in window", len(releases))
    if not releases:
        return []

    if fetch_details:
        for i, release in enumerate(releases):
            if release["has_detail"]:
                _enrich_with_details(release, headers)
                if i < len(releases) - 1:
                    time.sleep(0.75)

    if group_by_date:
        return _group_by_date(releases)
    return [_to_entry(r) for r in releases]


def _enrich_with_details(release: dict, headers: dict) -> None:
    """Fetch the detail page and extract CVEs, exploited flag, and impacts."""
    try:
        resp = requests.get(release["url"], headers=headers, timeout=30)
        resp.raise_for_status()
    except Exception:
        logger.warning(
            "Apple: failed to fetch detail page %s", release["url"]
        )
        return

    soup = BeautifulSoup(resp.content, "html.parser")
    text = soup.get_text()

    release["cves"] = sorted(set(_CVE_PATTERN.findall(text)))
    release["actively_exploited"] = _EXPLOITED_PATTERN.search(text) is not None

    # Component names from <h3> tags
    components: list[str] = []
    for h3 in soup.find_all("h3"):
        name = h3.get_text(strip=True)
        if (
            name
            and len(name) < 60
            and name not in _SKIP_HEADINGS
            and not _CVE_PATTERN.search(name)
            and name not in components
        ):
            components.append(name)
    release["components"] = components[:15]

    # Impact descriptions follow "Impact:" labels
    impacts: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("impact:"):
            impact_text = stripped[7:].strip()
            if impact_text and len(impact_text) < 300 and impact_text not in impacts:
                impacts.append(impact_text)
    release["impacts"] = impacts[:5]


def _to_entry(release: dict) -> ThreatEntry:
    """Convert a single release dict into a ThreatEntry."""
    actively_exploited: bool = release.get("actively_exploited", False)
    cves: list[str] = release.get("cves", [])
    available_for: str = release.get("available_for", "")
    impacts: list[str] = release.get("impacts", [])
    name: str = release["name"]

    severity = "Critical" if actively_exploited else "Medium"

    desc_parts: list[str] = []
    if actively_exploited:
        desc_parts.append("ACTIVELY EXPLOITED")
    if cves:
        desc_parts.append(f"{len(cves)} CVEs patched")
    if available_for:
        desc_parts.append(f"Available for: {available_for}")
    if impacts:
        desc_parts.append("Impacts include: " + "; ".join(impacts[:2]))

    description = " — ".join(desc_parts) if desc_parts else name

    return ThreatEntry(
        title=name,
        source="Apple Security",
        date=release["date"],
        severity=severity,
        cves=cves,
        description=description[:500],
        url=release["url"],
    )


def _group_by_date(releases: list[dict]) -> list[ThreatEntry]:
    """Consolidate same-day Apple releases into a single ThreatEntry."""
    by_date: dict[str, list[dict]] = defaultdict(list)
    for r in releases:
        by_date[r["date"].strftime("%Y-%m-%d")].append(r)

    entries: list[ThreatEntry] = []
    for date_key, day_releases in sorted(by_date.items(), reverse=True):
        if len(day_releases) == 1:
            entries.append(_to_entry(day_releases[0]))
            continue

        names = [r["name"] for r in day_releases]
        all_cves = sorted({cve for r in day_releases for cve in r.get("cves", [])})
        any_exploited = any(r.get("actively_exploited", False) for r in day_releases)
        all_impacts = list(
            {impact for r in day_releases for impact in r.get("impacts", [])}
        )

        # Prefer the first release that has a detail page as the canonical URL
        primary = next((r for r in day_releases if r.get("has_detail")), day_releases[0])

        severity = "Critical" if any_exploited else "Medium"
        title = f"Apple Security Updates — {date_key}"

        desc_parts: list[str] = []
        if any_exploited:
            desc_parts.append("ACTIVELY EXPLOITED")
        desc_parts.append(f"Apple released updates across: {', '.join(names)}")
        if all_cves:
            desc_parts.append(f"{len(all_cves)}+ CVEs patched")
        if all_impacts:
            desc_parts.append(
                "Including: " + "; ".join(list(all_impacts)[:2])
            )

        description = " — ".join(desc_parts)

        entries.append(
            ThreatEntry(
                title=title,
                source="Apple Security",
                date=primary["date"],
                severity=severity,
                cves=all_cves,
                description=description[:500],
                url=primary["url"],
            )
        )

    return entries
