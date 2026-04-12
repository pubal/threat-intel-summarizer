from __future__ import annotations
import logging, os, time
from pathlib import Path
import requests
from threat_brief.models import ThreatEntry

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
_INFOCON_EMOJI = {"green": "🟢", "yellow": "🟡", "orange": "🟠", "red": "🔴"}


def send_slack_notification(
    config: dict,
    entries: list[ThreatEntry],
    new_fingerprints: set[str] | None,
    filepath: Path,
    lookback: int,
    infocon_level: str,
) -> None:
    slack_cfg = config.get("notifications", {}).get("slack", {})
    if not slack_cfg.get("enabled", False):
        return

    webhook_url = slack_cfg.get("webhook_url", "") or os.environ.get("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        logger.warning(
            "Slack notifications enabled but no webhook URL configured. "
            "Set notifications.slack.webhook_url or SLACK_WEBHOOK_URL env var."
        )
        return

    threshold = slack_cfg.get("severity_threshold", "critical").lower()
    threshold_rank = _SEVERITY_RANK.get(threshold, 3)

    # Filter items at or above threshold
    qualifying = [
        e for e in entries
        if _SEVERITY_RANK.get(e.severity.lower(), 0) >= threshold_rank
    ]
    if not qualifying:
        logger.info("Slack: no items meet severity threshold '%s' — skipping notification", threshold)
        return

    # Build report URL
    include_link = slack_cfg.get("include_link_to_report", True)
    report_base_url = slack_cfg.get("report_base_url", "").rstrip("/")
    if report_base_url:
        report_url = f"{report_base_url}/reports/{filepath.name}"
    else:
        report_url = filepath.resolve().as_uri()

    # Header emoji and label
    critical_items = [e for e in qualifying if e.severity.lower() == "critical"]
    if critical_items:
        header_emoji, severity_label = "🚨", "Critical"
    elif any(e.severity.lower() == "high" for e in qualifying):
        header_emoji, severity_label = "⚠️", "High"
    else:
        header_emoji, severity_label = "ℹ️", "Medium"

    header_text = f"{header_emoji} Threat Brief — {len(qualifying)} {severity_label} Item{'s' if len(qualifying) != 1 else ''}"

    # InfoCon context
    infocon_emoji = _INFOCON_EMOJI.get(infocon_level.lower(), "⚪") if infocon_level else ""
    infocon_str = f"InfoCon: {infocon_emoji} {infocon_level.upper()}" if infocon_level else ""
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    context_parts = [ts, f"{lookback}h window"]
    if infocon_str:
        context_parts.append(infocon_str)
    context_text = " · ".join(context_parts)

    # Build item blocks (up to 10)
    from threat_brief.delta import item_fingerprint
    display_items = qualifying[:10]
    overflow = len(qualifying) - 10

    item_blocks = []
    for e in display_items:
        is_new = new_fingerprints is not None and item_fingerprint(e) in new_fingerprints
        title_prefix = "🆕 " if is_new else ""
        title_text = f"*{title_prefix}{e.title}*"
        cve_str = " ".join(f"`{c}`" for c in e.cves[:5]) if e.cves else ""
        cve_more = f" _+{len(e.cves) - 5} more_" if len(e.cves) > 5 else ""
        summary = e.description[:120].replace("\n", " ") if e.description else ""
        detail_parts = [f"_{e.source}_"]
        if cve_str:
            detail_parts.append(cve_str + cve_more)
        if summary:
            detail_parts.append(summary)
        detail_text = "  ".join(detail_parts)
        item_blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"{title_text}\n{detail_text}"}
        })

    overflow_block = []
    if overflow > 0:
        overflow_block = [{"type": "section", "text": {"type": "mrkdwn", "text": f"_...and {overflow} more_"}}]

    # Actions block
    actions_block = []
    if include_link:
        actions_block = [{
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": {"type": "plain_text", "text": "View Full Report"},
                "url": report_url,
            }]
        }]

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": header_text}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": context_text}]},
        {"type": "divider"},
        *item_blocks,
        *overflow_block,
        {"type": "divider"},
        *actions_block,
    ]

    payload = {"blocks": blocks}
    _post_with_retry(webhook_url, payload)


def _post_with_retry(webhook_url: str, payload: dict) -> None:
    for attempt, delay in enumerate([0, 1, 2, 4]):
        if delay:
            time.sleep(delay)
        try:
            resp = requests.post(webhook_url, json=payload, timeout=10)
        except requests.RequestException as exc:
            logger.warning("Slack notification: request error (attempt %d): %s", attempt + 1, exc)
            continue
        if resp.status_code == 200 and resp.text == "ok":
            logger.info("Slack notification sent successfully")
            return
        logger.warning(
            "Slack notification: unexpected response (attempt %d): status=%d body=%s",
            attempt + 1, resp.status_code, resp.text[:200],
        )
    logger.error("Slack notification failed after all retries — continuing without notification")
