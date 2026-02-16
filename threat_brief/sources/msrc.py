from __future__ import annotations

import logging
from datetime import datetime, timezone

import requests

from threat_brief.models import ThreatEntry

logger = logging.getLogger(__name__)


def fetch_msrc(url: str, cutoff: datetime) -> list[ThreatEntry]:
    """Fetch Microsoft Security Response Center updates via CVRF API v3.0."""
    logger.info("Fetching MSRC updates...")
    try:
        resp = requests.get(url, timeout=30, headers={"Accept": "application/json"})
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        logger.exception("Failed to fetch MSRC updates list")
        return []

    entries: list[ThreatEntry] = []
    for update in data.get("value", []):
        try:
            release_date = datetime.fromisoformat(
                update.get("CurrentReleaseDate", "").replace("Z", "+00:00")
            )
        except (ValueError, TypeError):
            continue

        if release_date < cutoff:
            continue

        update_id = update.get("ID", "")
        # Fetch the individual CVRF document for CVE details
        cves = _fetch_cves_for_update(url.rsplit("/", 1)[0], update_id)

        entries.append(
            ThreatEntry(
                title=f"MSRC {update_id}: {update.get('DocumentTitle', 'Security Update')}",
                source="MSRC",
                date=release_date,
                severity="High",
                cves=cves,
                description=update.get("DocumentTitle", ""),
                url=f"https://msrc.microsoft.com/update-guide/releaseNote/{update_id}",
            )
        )

    logger.info("MSRC: found %d entries in window", len(entries))
    return entries


def _fetch_cves_for_update(base_url: str, update_id: str) -> list[str]:
    """Try to pull CVE IDs from a specific CVRF document."""
    try:
        resp = requests.get(
            f"{base_url}/cvrf/{update_id}",
            timeout=15,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        doc = resp.json()
        vulns = doc.get("Vulnerability", [])
        return [v.get("CVE", "") for v in vulns if v.get("CVE")][:20]
    except Exception:
        logger.debug("Could not fetch CVE details for MSRC %s", update_id)
        return []
