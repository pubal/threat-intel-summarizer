from __future__ import annotations

import logging
import os
from collections import Counter
from datetime import datetime, timezone

import requests

from threat_brief.models import ThreatEntry

logger = logging.getLogger(__name__)

_API_URL = "https://api.github.com/advisories"
_ADVISORIES_BROWSE_URL = "https://github.com/advisories?query=type%3Areviewed"

# Map language/framework names (lowercased) to GitHub Advisory ecosystems
_LANG_TO_ECOSYSTEM: dict[str, str] = {
    "python": "pip",
    "javascript": "npm",
    "node": "npm",
    "node.js": "npm",
    "nodejs": "npm",
    "typescript": "npm",
    "ts": "npm",
    ".net": "nuget",
    "c#": "nuget",
    "dotnet": "nuget",
    "java": "maven",
    "go": "go",
    "golang": "go",
    "ruby": "rubygems",
    "rust": "cargo",
    "php": "composer",
}

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def _get_ecosystems(org_profile: dict) -> list[str] | None:
    """Map tech_stack languages to GitHub Advisory ecosystems.

    Returns None when no languages are configured — fetch all ecosystems
    rather than silently skipping the source.
    """
    langs = org_profile.get("tech_stack", {}).get("languages_and_frameworks", [])
    if not langs:
        return None

    ecosystems: set[str] = set()
    for lang in langs:
        normalized = lang.lower().strip()
        # Exact match
        if normalized in _LANG_TO_ECOSYSTEM:
            ecosystems.add(_LANG_TO_ECOSYSTEM[normalized])
            continue
        # Partial match: "Python 3.11" → starts with "python" → "pip"
        for token, eco in _LANG_TO_ECOSYSTEM.items():
            if normalized.startswith(token) or token in normalized:
                ecosystems.add(eco)
                break

    return list(ecosystems) if ecosystems else None


def _get_named_packages(org_profile: dict) -> set[str]:
    """Lowercase first-word tokens for packages named in the org profile.

    Used to detect when an advisory directly affects a known tool
    (e.g. org lists "Django" and there's a Django advisory).
    """
    tech_stack = org_profile.get("tech_stack", {})
    named: set[str] = set()
    for cat in ("applications", "infrastructure", "security_tools"):
        for item in tech_stack.get(cat, []):
            named.add(item.lower().split()[0])
    return named


def _build_session(token: str) -> requests.Session:
    sess = requests.Session()
    sess.headers.update({
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "threat-brief/1.0",
    })
    if token:
        sess.headers["Authorization"] = f"Bearer {token}"
    return sess


def _fetch_all_pages(
    session: requests.Session,
    cutoff: datetime,
    ecosystem: str | None,
) -> list[dict]:
    """Fetch pages of newly published reviewed advisories for a given ecosystem (or all).

    Uses the 'published' filter param (>ISO format) to return only advisories
    first published within the time window — not re-reviews of older entries.
    Paginates until the API returns an empty page.
    """
    results: list[dict] = []
    params: dict = {
        "type": "reviewed",
        "per_page": 100,
        "sort": "published",
        "direction": "desc",
        "published": f">{cutoff.strftime('%Y-%m-%dT%H:%M:%SZ')}",
    }
    if ecosystem:
        params["ecosystem"] = ecosystem

    page = 1
    while True:
        params["page"] = page
        try:
            resp = session.get(_API_URL, params=params, timeout=30)
        except requests.ConnectionError:
            logger.warning("GitHub Advisories: connection error on page %d", page)
            break

        if resp.status_code == 403:
            logger.warning(
                "GitHub Advisories: rate limit hit (403). "
                "Add a github_token to config or set GITHUB_TOKEN env var "
                "for 5,000 requests/hour instead of 60."
            )
            break

        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            logger.warning("GitHub Advisories: HTTP error on page %d: %s", page, exc)
            break

        data = resp.json()
        if not data:
            break

        results.extend(data)

        if len(data) < 100:
            break  # Last page

        page += 1

    return results


def _advisory_id(adv: dict) -> str:
    """Return CVE ID if present, else the GHSA ID."""
    return adv.get("cve_id") or adv.get("ghsa_id", "")


def _advisory_package(adv: dict) -> tuple[str, str]:
    """Return (package_name, ecosystem) from the first vulnerability entry."""
    vulns = adv.get("vulnerabilities", [])
    if vulns:
        pkg = vulns[0].get("package", {})
        return pkg.get("name", ""), pkg.get("ecosystem", "")
    return "", ""


def _format_advisory_line(
    adv: dict, named_packages: set[str], new_ids: set[str]
) -> str:
    """Format one advisory as a compact one-liner for the description."""
    pkg_name, eco = _advisory_package(adv)
    adv_id = _advisory_id(adv)
    summary = adv.get("summary", "")[:120]

    direct = bool(pkg_name) and pkg_name.lower() in named_packages
    prefix = "DIRECT MATCH: " if direct else ""
    new_tag = " [NEW]" if adv_id and adv_id in new_ids else ""

    eco_part = f" ({eco})" if eco else ""
    pkg_part = f"{pkg_name}{eco_part}" if pkg_name else eco
    id_part = f" {adv_id}" if adv_id else ""

    return f"{prefix}{pkg_part}{id_part} — {summary}{new_tag}"


def fetch_github_advisories(url: str, cutoff: datetime, config: dict) -> list[ThreatEntry]:
    """Fetch GitHub Advisory Database and aggregate into a single ThreatEntry.

    Accepts the full config dict (not just the source config) so it can
    access org_profile for ecosystem and package matching.
    """
    source_cfg = config.get("sources", {}).get("github_advisories", {})
    org_profile = config.get("org_profile", {})

    logger.info("Fetching GitHub Security Advisories...")

    token = source_cfg.get("github_token", "") or os.environ.get("GITHUB_TOKEN", "")
    min_severity = source_cfg.get("min_severity", "medium").lower()
    min_rank = _SEVERITY_RANK.get(min_severity, 2)

    ecosystems = _get_ecosystems(org_profile)
    named_packages = _get_named_packages(org_profile)
    session = _build_session(token)

    # Fetch — one paginated call per ecosystem, or one for all
    raw: list[dict] = []
    if ecosystems:
        seen_ghsa: set[str] = set()
        for eco in sorted(ecosystems):  # sorted for determinism
            for adv in _fetch_all_pages(session, cutoff, eco):
                ghsa = adv.get("ghsa_id", "")
                if ghsa not in seen_ghsa:
                    seen_ghsa.add(ghsa)
                    raw.append(adv)
    else:
        raw = _fetch_all_pages(session, cutoff, None)

    # Post-filter by minimum severity (date already filtered in _fetch_all_pages)
    advisories: list[dict] = [
        adv for adv in raw
        if _SEVERITY_RANK.get((adv.get("severity") or "").lower(), 0) >= min_rank
    ]

    if not advisories:
        logger.info("GitHub Advisories: no advisories in window")
        return []

    # CVEs seen in previous run for inline [NEW] tagging within description
    manifest = config.get("_manifest") or {}
    prev_ids: set[str] = set(manifest.get("cves_seen", []))
    new_ids: set[str] = {
        _advisory_id(a) for a in advisories
        if _advisory_id(a) and _advisory_id(a) not in prev_ids
    }

    # Bucket by severity
    critical = [a for a in advisories if (a.get("severity") or "").lower() == "critical"]
    high = [a for a in advisories if (a.get("severity") or "").lower() == "high"]
    medium = [a for a in advisories if (a.get("severity") or "").lower() == "medium"]

    total = len(advisories)

    # Title
    title = (
        f"GitHub Security Advisories — {total} advisories "
        f"({len(critical)} critical, {len(high)} high)"
    )

    # Description — tiered: critical individual, high individual, medium rollup
    desc_parts: list[str] = []

    if critical:
        lines = [f"Critical ({len(critical)}):"]
        for adv in critical[:10]:
            lines.append("  " + _format_advisory_line(adv, named_packages, new_ids))
        if len(critical) > 10:
            lines.append(f"  ...and {len(critical) - 10} more")
        desc_parts.append("\n".join(lines))

    if high:
        lines = [f"High ({len(high)}):"]
        for adv in high[:10]:
            lines.append("  " + _format_advisory_line(adv, named_packages, new_ids))
        if len(high) > 10:
            lines.append(f"  ...and {len(high) - 10} more")
        desc_parts.append("\n".join(lines))

    if medium:
        eco_counts: Counter = Counter()
        for adv in medium:
            _, eco = _advisory_package(adv)
            eco_counts[eco or "other"] += 1
        eco_str = ", ".join(
            f"{eco} ({n})" for eco, n in eco_counts.most_common()
        )
        desc_parts.append(f"Medium ({len(medium)}): {eco_str}")

    if ecosystems:
        desc_parts.append(f"Ecosystems: {', '.join(sorted(ecosystems))}")

    description = "\n".join(desc_parts)

    # Overall severity = highest found
    if critical:
        severity = "Critical"
    elif high:
        severity = "High"
    else:
        severity = "Medium"

    # All CVE IDs (not GHSA-only IDs) for the fingerprint and delta tracking
    cve_ids = sorted({a.get("cve_id") for a in advisories if a.get("cve_id")})

    # Most recent published_at across all advisories
    most_recent = max(
        (
            datetime.fromisoformat(a["published_at"].replace("Z", "+00:00"))
            for a in advisories
            if a.get("published_at")
        ),
        default=datetime.now(timezone.utc),
    )

    logger.info(
        "GitHub Advisories: %d total (%d critical, %d high, %d medium)",
        total, len(critical), len(high), len(medium),
    )

    return [
        ThreatEntry(
            title=title,
            source="GitHub Advisories",
            date=most_recent,
            severity=severity,
            cves=cve_ids,
            description=description,
            url=_ADVISORIES_BROWSE_URL,
        )
    ]
