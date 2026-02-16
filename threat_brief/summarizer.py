from __future__ import annotations

import json
import logging

import requests

from threat_brief.models import ThreatEntry

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a threat intelligence analyst at REDACTED, a financial services "
    "and banking technology company. Summarize these threat intel items, prioritizing "
    "anything relevant to financial services, banking infrastructure, payment systems, "
    "cloud services (AWS), and Windows/Active Directory environments. Flag any items "
    "requiring immediate action.\n\n"
    "Format your response as a Markdown briefing with these exact sections:\n"
    "## TL;DR — Executive Summary\n"
    "(3-5 bullet points for leadership)\n\n"
    "## Critical / Action Required\n"
    "(Items needing immediate response — patches, mitigations, IOC blocks)\n\n"
    "## High Relevance\n"
    "(Items relevant to our stack but not immediately actionable)\n\n"
    "## Awareness\n"
    "(General threat landscape items worth tracking)\n\n"
    "For each item you mention, include a Markdown link to its source URL, e.g. "
    "[CVE-2024-1234](https://nvd.nist.gov/vuln/detail/CVE-2024-1234). "
    "This ensures the briefing has clickable references.\n\n"
    "If a section has no items, write 'None at this time.'"
)


def summarize(
    entries: list[ThreatEntry],
    endpoint: str,
    model: str,
    max_tokens: int = 4096,
    temperature: float = 0.3,
) -> str:
    """Send aggregated threat entries to a local LLM for summarization."""
    if not entries:
        return _empty_report()

    items_text = "\n\n".join(
        f"### {i+1}. {e.title}\n"
        f"- Source: {e.source}\n"
        f"- Date: {e.date.strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"- Severity: {e.severity}\n"
        f"- CVEs: {', '.join(e.cves) if e.cves else 'N/A'}\n"
        f"- Description: {e.description}\n"
        f"- URL: {e.url}"
        for i, e in enumerate(entries)
    )

    user_prompt = (
        f"Here are {len(entries)} threat intelligence items from the last reporting window:\n\n"
        f"{items_text}\n\n"
        "Please produce the briefing now."
    )

    logger.info("Sending %d items to LLM at %s (model: %s)", len(entries), endpoint, model)

    try:
        resp = requests.post(
            f"{endpoint}/chat/completions",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": temperature,
            },
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]
    except requests.ConnectionError:
        logger.error(
            "Cannot connect to LLM endpoint at %s. Is LM Studio running?", endpoint
        )
        return _fallback_report(entries)
    except Exception:
        logger.exception("LLM summarization failed")
        return _fallback_report(entries)


def _empty_report() -> str:
    return (
        "# Threat Intelligence Briefing\n\n"
        "No threat intelligence items found in the reporting window.\n"
    )


def _fallback_report(entries: list[ThreatEntry]) -> str:
    """Generate a basic report without LLM when the endpoint is unavailable."""
    lines = [
        "# Threat Intelligence Briefing\n",
        "> **Note:** LLM summarization unavailable. Showing raw categorized items.\n\n",
        "## Critical / Action Required\n",
    ]
    critical = [e for e in entries if e.severity == "Critical"]
    high = [e for e in entries if e.severity == "High"]
    rest = [e for e in entries if e.severity not in ("Critical", "High")]

    if critical:
        lines.extend(e.summary_line() + "\n" for e in critical)
    else:
        lines.append("None at this time.\n")

    lines.append("\n## High Relevance\n")
    if high:
        lines.extend(e.summary_line() + "\n" for e in high)
    else:
        lines.append("None at this time.\n")

    lines.append("\n## Awareness\n")
    if rest:
        lines.extend(e.summary_line() + "\n" for e in rest)
    else:
        lines.append("None at this time.\n")

    return "".join(lines)
