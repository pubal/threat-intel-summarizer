from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ThreatEntry:
    title: str
    source: str
    date: datetime
    severity: str
    cves: list[str] = field(default_factory=list)
    description: str = ""
    url: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "source": self.source,
            "date": self.date.isoformat(),
            "severity": self.severity,
            "cves": self.cves,
            "description": self.description,
            "url": self.url,
        }

    def summary_line(self) -> str:
        cve_str = ", ".join(self.cves) if self.cves else "N/A"
        return (
            f"- **{self.title}** ({self.source})\n"
            f"  Severity: {self.severity} | CVEs: {cve_str}\n"
            f"  {self.description[:200]}\n"
            f"  Link: {self.url}\n"
        )
