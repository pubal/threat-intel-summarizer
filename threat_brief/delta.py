"""Delta tracking — fingerprint items and detect new entries since the last run."""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from threat_brief.models import ThreatEntry

logger = logging.getLogger(__name__)

MANIFEST_FILENAME = ".last_run.json"


def item_fingerprint(entry: ThreatEntry) -> str:
    """Stable hash of source + title + sorted CVE list.

    Intentionally excludes description and date — those can change between
    runs for the same advisory without it being a genuinely new item.
    """
    key = f"{entry.source}|{entry.title}|{','.join(sorted(entry.cves))}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def load_manifest(reports_dir: str) -> dict | None:
    """Load the previous run manifest. Returns None if missing or unreadable."""
    path = Path(reports_dir) / MANIFEST_FILENAME
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        logger.warning("Could not read last-run manifest at %s", path)
        return None


def save_manifest(entries: list[ThreatEntry], reports_dir: str) -> None:
    """Write a manifest of this run's fingerprints.

    Always called after every successful run, regardless of whether delta
    tracking is enabled — so future runs always have accurate baseline data.
    """
    dir_path = Path(reports_dir)
    dir_path.mkdir(parents=True, exist_ok=True)
    manifest = {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "fingerprints": [item_fingerprint(e) for e in entries],
        "cves_seen": sorted({cve for e in entries for cve in e.cves}),
    }
    try:
        with open(dir_path / MANIFEST_FILENAME, "w") as f:
            json.dump(manifest, f, indent=2)
    except Exception:
        logger.warning("Could not save run manifest", exc_info=True)


def get_new_fingerprints(
    entries: list[ThreatEntry], manifest: dict | None
) -> set[str]:
    """Return fingerprints of items not present in the previous manifest.

    Returns an empty set when no manifest exists (first run) — on a first
    run everything is technically new, but tagging it all as [NEW] would be
    meaningless noise.
    """
    if manifest is None:
        return set()
    prev = set(manifest.get("fingerprints", []))
    return {item_fingerprint(e) for e in entries if item_fingerprint(e) not in prev}
