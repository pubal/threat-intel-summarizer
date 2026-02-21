from __future__ import annotations

import logging
import os
import subprocess
import sys
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click
import markdown
import yaml

from threat_brief.html_template import HTML_TEMPLATE

from threat_brief.models import ThreatEntry
from threat_brief.sources import (
    fetch_aws_bulletins,
    fetch_cisa_kev,
    fetch_hackernews,
    fetch_isc,
    fetch_infocon,
    fetch_krebs,
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
    user_agent = config.get("user_agent", "")
    all_entries: list[ThreatEntry] = []

    fetchers = [
        ("CISA KEV", fetch_cisa_kev, sources.get("cisa_kev", {}).get("url", "")),
        ("MSRC", fetch_msrc, sources.get("msrc", {}).get("url", "")),
        ("AWS Bulletins", fetch_aws_bulletins, sources.get("aws_security", {}).get("url", "")),
        ("Hacker News", fetch_hackernews, sources.get("hackernews_threatintel", {}).get("url", "")),
        ("Krebs on Security", fetch_krebs, sources.get("krebs", {}).get("url", "")),
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

    # SANS ISC (needs user_agent as extra arg)
    isc_url = sources.get("isc_sans", {}).get("url", "")
    if isc_url:
        try:
            entries = fetch_isc(isc_url, cutoff, user_agent)
            all_entries.extend(entries)
            click.echo(f"  [SANS ISC] {len(entries)} items")
        except Exception:
            logger.exception("Source SANS ISC failed")
            click.echo("  [SANS ISC] FAILED — skipping", err=True)

    # Sort by date descending
    all_entries.sort(key=lambda e: e.date, reverse=True)
    return all_entries


def _write_report(content: str, reports_dir: str, ext: str = ".html") -> Path:
    """Write report to a dated file."""
    path = Path(reports_dir)
    path.mkdir(parents=True, exist_ok=True)
    filename = f"threat-brief-{datetime.now().strftime('%Y-%m-%d_%H%M')}{ext}"
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


def _build_profile_footer(org_profile: dict) -> str:
    """Build HTML footer showing org profile context, or empty string."""
    company = org_profile.get("company_name", "")
    industries = org_profile.get("industry", [])
    if not company and not industries:
        return ""

    parts = []
    if company:
        parts.append(f"Tailored for <strong>{company}</strong>")
    if industries:
        parts.append(f"Industry: {', '.join(industries)}")

    return (
        '<footer class="report-footer">'
        f'{"  &middot;  ".join(parts)}'
        "</footer>"
    )


@click.group(invoke_without_command=True)
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
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["html", "md"], case_sensitive=False),
    default="html",
    help="Output format (default: html)",
)
@click.pass_context
def main(ctx: click.Context, config_path: str, hours: int | None, dry_run: bool, verbose: bool, output_format: str) -> None:
    """threat-brief — Daily threat intelligence briefing generator."""
    # If a subcommand was invoked, store config_path for it and return
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path

    if ctx.invoked_subcommand is not None:
        return

    _setup_logging(verbose)

    config = _load_config(config_path)
    org_profile = config.get("org_profile", {})
    company_name = org_profile.get("company_name", "")
    lookback = hours if hours is not None else config.get("default_hours", 48)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback)

    click.echo(f"Threat Brief — lookback: {lookback}h (cutoff: {cutoff.strftime('%Y-%m-%d %H:%M UTC')})")
    if company_name:
        click.echo(f"Organization: {company_name}")
    click.echo("Fetching sources...")

    entries = _fetch_all(config, cutoff)

    # Fetch InfoCon level separately
    sources = config.get("sources", {})
    user_agent = config.get("user_agent", "")
    infocon_url = sources.get("isc_sans", {}).get("infocon_url", "")
    infocon_level = ""
    if infocon_url:
        infocon_level = fetch_infocon(infocon_url, user_agent)
        click.echo(f"  [InfoCon] Level: {infocon_level.upper()}")

    click.echo(f"\nTotal items: {len(entries)}")

    if dry_run:
        output = _dry_run_output(entries)
    else:
        click.echo("\nGenerating LLM summary...")
        llm_cfg = config.get("llm", {})

        # Build source list dynamically from configured sources
        source_names = "CISA KEV, MSRC, AWS Security Bulletins, The Hacker News, Krebs on Security, SANS ISC"

        header = (
            f"# Threat Intelligence Briefing\n"
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  \n"
            f"**Window:** Last {lookback} hours  \n"
            f"**Sources:** {source_names}  \n"
            f"**Items analyzed:** {len(entries)}\n\n---\n\n"
        )
        summary = summarize(
            entries,
            endpoint=llm_cfg.get("endpoint", "http://localhost:1234/v1"),
            model=llm_cfg.get("model", "local-model"),
            max_tokens=llm_cfg.get("max_tokens", 4096),
            temperature=llm_cfg.get("temperature", 0.3),
            infocon_level=infocon_level,
            org_profile=org_profile,
        )
        output = header + summary

    # Convert to HTML if requested
    if output_format == "html":
        body_html = markdown.markdown(output, extensions=["extra", "sane_lists"])
        generated_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        if infocon_level:
            infocon_badge = (
                f'<span class="infocon-badge infocon-{infocon_level}">'
                f"InfoCon: {infocon_level.upper()}</span>"
            )
        else:
            infocon_badge = ""
        profile_footer = _build_profile_footer(org_profile)
        final_output = HTML_TEMPLATE.format(
            generated=generated_ts,
            window=f"Last {lookback} hours",
            item_count=len(entries),
            body=body_html,
            infocon_badge=infocon_badge,
            profile_footer=profile_footer,
        )
        ext = ".html"
    else:
        final_output = output
        ext = ".md"

    # Print to stdout (Markdown version for readability in terminal)
    click.echo("\n" + "=" * 60)
    click.echo(output)

    # Write to file
    reports_dir = config.get("reports_dir", "./reports")
    filepath = _write_report(final_output, reports_dir, ext=ext)
    click.echo(f"\nReport saved to: {filepath}")

    # Auto-open HTML in browser
    if output_format == "html":
        webbrowser.open(filepath.resolve().as_uri())

    # macOS notification
    critical_count = sum(1 for e in entries if e.severity == "Critical")
    _notify(
        "Threat Brief Ready",
        f"{len(entries)} items analyzed, {critical_count} critical. Report: {filepath.name}",
    )


@main.command()
@click.pass_context
def init(ctx: click.Context) -> None:
    """Interactive setup wizard for org_profile configuration."""
    config_path = ctx.obj["config_path"]

    click.echo("threat-brief — Organization Profile Setup")
    click.echo("Press Enter to skip any question.\n")

    # Company name
    company_name = click.prompt(
        "Company name", default="", show_default=False
    ).strip()

    # Industry
    industry_input = click.prompt(
        "Industry (comma-separated, e.g. Financial Services, FinTech, Healthcare)",
        default="", show_default=False,
    ).strip()
    industries = [i.strip() for i in industry_input.split(",") if i.strip()] if industry_input else []

    # Tech stack categories
    click.echo("\nTech Stack (press Enter to skip any category):")

    os_input = click.prompt(
        "  Operating systems (e.g. Windows 11, macOS, Ubuntu)",
        default="", show_default=False,
    ).strip()
    operating_systems = [i.strip() for i in os_input.split(",") if i.strip()] if os_input else []

    infra_input = click.prompt(
        "  Infrastructure (e.g. Active Directory, AWS, Azure)",
        default="", show_default=False,
    ).strip()
    infrastructure = [i.strip() for i in infra_input.split(",") if i.strip()] if infra_input else []

    apps_input = click.prompt(
        "  Applications (e.g. Microsoft 365, SolarWinds, Ivanti)",
        default="", show_default=False,
    ).strip()
    applications = [i.strip() for i in apps_input.split(",") if i.strip()] if apps_input else []

    langs_input = click.prompt(
        "  Languages/frameworks (e.g. Python, .NET, Node.js)",
        default="", show_default=False,
    ).strip()
    languages = [i.strip() for i in langs_input.split(",") if i.strip()] if langs_input else []

    sec_input = click.prompt(
        "  Security tools (e.g. CrowdStrike, Splunk, Tenable)",
        default="", show_default=False,
    ).strip()
    security_tools = [i.strip() for i in sec_input.split(",") if i.strip()] if sec_input else []

    # Build org_profile with only non-empty fields
    org_profile: dict = {}
    if company_name:
        org_profile["company_name"] = company_name
    if industries:
        org_profile["industry"] = industries

    tech_stack: dict = {}
    if operating_systems:
        tech_stack["operating_systems"] = operating_systems
    if infrastructure:
        tech_stack["infrastructure"] = infrastructure
    if applications:
        tech_stack["applications"] = applications
    if languages:
        tech_stack["languages_and_frameworks"] = languages
    if security_tools:
        tech_stack["security_tools"] = security_tools
    if tech_stack:
        org_profile["tech_stack"] = tech_stack

    if not org_profile:
        click.echo("\nNo profile data provided. Config unchanged.")
        return

    # Read existing config, merge, write back
    with open(config_path) as f:
        config = yaml.safe_load(f) or {}

    config["org_profile"] = org_profile

    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    click.echo(f"\nOrg profile saved to {config_path}:")
    click.echo(yaml.dump({"org_profile": org_profile}, default_flow_style=False, sort_keys=False))


def _notify(title: str, message: str) -> None:
    """Send a macOS notification."""
    try:
        subprocess.run(
            [
                "osascript",
                "-e",
                f'display notification "{message}" with title "{title}"',
            ],
            check=True,
            capture_output=True,
        )
    except Exception:
        logger.debug("macOS notification failed", exc_info=True)


if __name__ == "__main__":
    main()
