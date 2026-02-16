from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click
import yaml

from threat_brief.models import ThreatEntry
from threat_brief.sources import (
    fetch_aws_bulletins,
    fetch_cisa_kev,
    fetch_hackernews,
    fetch_msrc,
)
from threat_brief.summarizer import summarize

logger = logging.getLogger("threat_brief")


def _load_config(config_path: str) -> dict:
    with open(config_path) as f:
        return yaml.safe_load(f)


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _fetch_all(config: dict, cutoff: datetime) -> list[ThreatEntry]:
    """Fetch from all sources, tolerating individual failures."""
    sources = config.get("sources", {})
    all_entries: list[ThreatEntry] = []

    fetchers = [
        ("CISA KEV", fetch_cisa_kev, sources.get("cisa_kev", {}).get("url", "")),
        ("MSRC", fetch_msrc, sources.get("msrc", {}).get("url", "")),
        ("AWS Bulletins", fetch_aws_bulletins, sources.get("aws_security", {}).get("url", "")),
        ("Hacker News", fetch_hackernews, sources.get("hackernews_threatintel", {}).get("url", "")),
    ]

    for name, fetcher, url in fetchers:
        if not url:
            logger.warning("No URL configured for %s, skipping", name)
            continue
        try:
            entries = fetcher(url, cutoff)
            all_entries.extend(entries)
            click.echo(f"  [{name}] {len(entries)} items")
        except Exception:
            logger.exception("Source %s failed", name)
            click.echo(f"  [{name}] FAILED — skipping", err=True)

    # Sort by date descending
    all_entries.sort(key=lambda e: e.date, reverse=True)
    return all_entries


def _write_report(content: str, reports_dir: str) -> Path:
    """Write report to a dated file."""
    path = Path(reports_dir)
    path.mkdir(parents=True, exist_ok=True)
    filename = f"threat-brief-{datetime.now().strftime('%Y-%m-%d_%H%M')}.md"
    filepath = path / filename
    filepath.write_text(content, encoding="utf-8")
    return filepath


def _dry_run_output(entries: list[ThreatEntry]) -> str:
    """Format raw items for dry-run mode."""
    if not entries:
        return "No items found in the reporting window.\n"

    lines = [f"# Raw Threat Intel Items ({len(entries)} total)\n"]
    for i, e in enumerate(entries, 1):
        lines.append(
            f"## {i}. {e.title}\n"
            f"- **Source:** {e.source}\n"
            f"- **Date:** {e.date.strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"- **Severity:** {e.severity}\n"
            f"- **CVEs:** {', '.join(e.cves) if e.cves else 'N/A'}\n"
            f"- **Description:** {e.description}\n"
            f"- **URL:** {e.url}\n"
        )
    return "\n".join(lines)


@click.command()
@click.option(
    "--config",
    "config_path",
    default="config.yaml",
    type=click.Path(exists=True),
    help="Path to config.yaml",
)
@click.option(
    "--hours",
    default=None,
    type=int,
    help="Override the lookback window in hours (default: 48)",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Fetch and display raw items without LLM summarization",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def main(config_path: str, hours: int | None, dry_run: bool, verbose: bool) -> None:
    """threat-brief — Daily threat intelligence briefing generator."""
    _setup_logging(verbose)

    config = _load_config(config_path)
    lookback = hours if hours is not None else config.get("default_hours", 48)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback)

    click.echo(f"Threat Brief — lookback: {lookback}h (cutoff: {cutoff.strftime('%Y-%m-%d %H:%M UTC')})")
    click.echo("Fetching sources...")

    entries = _fetch_all(config, cutoff)
    click.echo(f"\nTotal items: {len(entries)}")

    if dry_run:
        output = _dry_run_output(entries)
    else:
        click.echo("\nGenerating LLM summary...")
        llm_cfg = config.get("llm", {})
        header = (
            f"# Threat Intelligence Briefing\n"
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  \n"
            f"**Window:** Last {lookback} hours  \n"
            f"**Sources:** CISA KEV, MSRC, AWS Security Bulletins, The Hacker News  \n"
            f"**Items analyzed:** {len(entries)}\n\n---\n\n"
        )
        summary = summarize(
            entries,
            endpoint=llm_cfg.get("endpoint", "http://localhost:1234/v1"),
            model=llm_cfg.get("model", "local-model"),
            max_tokens=llm_cfg.get("max_tokens", 4096),
            temperature=llm_cfg.get("temperature", 0.3),
        )
        output = header + summary

    # Print to stdout
    click.echo("\n" + "=" * 60)
    click.echo(output)

    # Write to file
    reports_dir = config.get("reports_dir", "./reports")
    filepath = _write_report(output, reports_dir)
    click.echo(f"\nReport saved to: {filepath}")


if __name__ == "__main__":
    main()
