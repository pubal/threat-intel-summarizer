from __future__ import annotations

import logging
from datetime import datetime, timezone

import requests

from threat_brief.models import ThreatEntry

logger = logging.getLogger(__name__)


def fetch_cisa_kev(url: str, cutoff: datetime) -> list[ThreatEntry]:
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    logger.info("Fetching CISA KEV catalog...")
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        logger.exception("Failed to fetch CISA KEV")
        return []

    entries: list[ThreatEntry] = []
    for vuln in data.get("vulnerabilities", []):
        try:
            date_added = datetime.strptime(
                vuln.get("dateAdded", ""), "%Y-%m-%d"
            ).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue

        if date_added < cutoff:
            continue

        entries.append(
            ThreatEntry(
                title=vuln.get("vulnerabilityName", "Unknown"),
                source="CISA KEV",
                date=date_added,
                severity="Critical",  # KEV entries are actively exploited
                cves=[vuln.get("cveID", "")] if vuln.get("cveID") else [],
                description=(
                    f"{vuln.get('shortDescription', '')} "
                    f"Vendor: {vuln.get('vendorProject', 'N/A')}, "
                    f"Product: {vuln.get('product', 'N/A')}. "
                    f"Required action: {vuln.get('requiredAction', 'N/A')}. "
                    f"Due date: {vuln.get('dueDate', 'N/A')}."
                ),
                url=f"https://nvd.nist.gov/vuln/detail/{vuln.get('cveID', '')}",
            )
        )

    logger.info("CISA KEV: found %d entries in window", len(entries))
    return entries
