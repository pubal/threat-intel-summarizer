"""Source registry — single place to define all threat intel sources."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .apple_security import fetch_apple_security
from .aws_bulletins import fetch_aws_bulletins
from .mandiant import fetch_mandiant
from .cisa_all import fetch_cisa_advisories
from .cisa_kev import fetch_cisa_kev
from .hackernews import fetch_hackernews
from .isc import fetch_isc
from .krebs import fetch_krebs
from .msrc import fetch_msrc


@dataclass
class SourceInfo:
    """Metadata for a single threat intel source."""

    key: str
    name: str
    description: str
    fetch_fn: Callable
    default_url: str
    extra_config: dict[str, str] = field(default_factory=dict)
    needs_user_agent: bool = False
    needs_source_cfg: bool = False


SOURCE_REGISTRY: list[SourceInfo] = [
    SourceInfo(
        key="apple_security",
        name="Apple Security",
        description="Apple security updates for iOS, macOS, watchOS, tvOS, Safari — with optional CVE detail enrichment",
        fetch_fn=fetch_apple_security,
        default_url="https://support.apple.com/en-us/100100",
        needs_source_cfg=True,
    ),
    SourceInfo(
        key="cisa_advisories",
        name="CISA Advisories",
        description="CISA Alerts & Advisories — CVEs, CVSS scores, sector tags, vendor/equipment details (ICS + cybersecurity)",
        fetch_fn=fetch_cisa_advisories,
        default_url="https://www.cisa.gov/cybersecurity-advisories/all.xml",
    ),
    SourceInfo(
        key="cisa_kev",
        name="CISA KEV",
        description="CISA Known Exploited Vulnerabilities catalog — actively exploited CVEs",
        fetch_fn=fetch_cisa_kev,
        default_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ),
    SourceInfo(
        key="msrc",
        name="MSRC",
        description="Microsoft Security Response Center — Patch Tuesday and out-of-band updates",
        fetch_fn=fetch_msrc,
        default_url="https://api.msrc.microsoft.com/cvrf/v3.0/updates",
    ),
    SourceInfo(
        key="aws_security",
        name="AWS Bulletins",
        description="AWS Security Bulletins — cloud infrastructure advisories",
        fetch_fn=fetch_aws_bulletins,
        default_url="https://aws.amazon.com/security/security-bulletins/",
    ),
    SourceInfo(
        key="hackernews_threatintel",
        name="The Hacker News",
        description="The Hacker News — cybersecurity news and threat reporting",
        fetch_fn=fetch_hackernews,
        default_url="https://feeds.feedburner.com/TheHackersNews",
    ),
    SourceInfo(
        key="krebs",
        name="Krebs on Security",
        description="Krebs on Security — investigative cybersecurity journalism",
        fetch_fn=fetch_krebs,
        default_url="https://krebsonsecurity.com/feed/",
    ),
    SourceInfo(
        key="mandiant",
        name="Mandiant",
        description="Google/Mandiant threat intelligence research — APT campaigns, threat actors, malware analysis, and exploitation trends",
        fetch_fn=fetch_mandiant,
        default_url="https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v",
    ),
    SourceInfo(
        key="isc_sans",
        name="SANS ISC",
        description="SANS Internet Storm Center — diary entries and InfoCon threat level",
        fetch_fn=fetch_isc,
        default_url="https://isc.sans.edu/rssfeed_full.xml",
        extra_config={"infocon_url": "https://isc.sans.edu/infocon.txt"},
        needs_user_agent=True,
    ),
]


def get_registry_by_key() -> dict[str, SourceInfo]:
    """Return registry as a dict keyed by config key."""
    return {s.key: s for s in SOURCE_REGISTRY}
