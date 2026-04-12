from __future__ import annotations

import html
import logging
import os
import re
import subprocess
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click
import markdown
import yaml

from threat_brief.delta import (
    get_new_fingerprints,
    item_fingerprint,
    load_manifest,
    save_manifest,
)
from threat_brief.html_template import HTML_TEMPLATE
from threat_brief.models import ThreatEntry
from threat_brief.sources import fetch_infocon
from threat_brief.sources.registry import SOURCE_REGISTRY, get_registry_by_key
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


def _is_source_enabled(source_cfg: dict) -> bool:
    """Check if a source is enabled. Missing sources default to enabled for backward compat."""
    return source_cfg.get("enabled", True)


def _get_enabled_sources(config: dict) -> list[str]:
    """Return display names of all enabled sources."""
    sources_cfg = config.get("sources", {})
    registry = get_registry_by_key()
    names = []
    for src in SOURCE_REGISTRY:
        cfg = sources_cfg.get(src.key, {})
        if _is_source_enabled(cfg):
            names.append(src.name)
    return names


def _fetch_all(
    config: dict, cutoff: datetime, manifest: dict | None = None
) -> list[ThreatEntry]:
    """Fetch from all enabled sources, tolerating individual failures."""
    sources_cfg = config.get("sources", {})
    user_agent = config.get("user_agent", "")
    all_entries: list[ThreatEntry] = []

    # Inject manifest so full-config sources can do inline [NEW] tagging
    full_config = {**config, "_manifest": manifest} if manifest else config

    for src in SOURCE_REGISTRY:
        cfg = sources_cfg.get(src.key, {})

        if not _is_source_enabled(cfg):
            click.echo(f"  [{src.name}] disabled — skipping")
            continue

        url = cfg.get("url", "")
        if not url:
            logger.warning("No URL configured for %s, skipping", src.name)
            continue

        try:
            if src.needs_user_agent:
                entries = src.fetch_fn(url, cutoff, user_agent)
            elif src.needs_source_cfg:
                entries = src.fetch_fn(url, cutoff, cfg)
            elif src.needs_full_config:
                entries = src.fetch_fn(url, cutoff, full_config)
            else:
                entries = src.fetch_fn(url, cutoff)
            all_entries.extend(entries)
            click.echo(f"  [{src.name}] {len(entries)} items")
        except Exception:
            logger.exception("Source %s failed", src.name)
            click.echo(f"  [{src.name}] FAILED — skipping", err=True)

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


def _dry_run_output(
    entries: list[ThreatEntry], new_fingerprints: set[str] | None = None
) -> str:
    """Format raw items for dry-run mode."""
    if not entries:
        return "No items found in the reporting window.\n"

    new_fps = new_fingerprints or set()
    lines = [f"# Raw Threat Intel Items ({len(entries)} total)\n"]
    for i, e in enumerate(entries, 1):
        cves = (
            ", ".join(
                f"[{c}](https://nvd.nist.gov/vuln/detail/{c})" for c in e.cves
            )
            if e.cves
            else "N/A"
        )
        new_badge = " [NEW]" if item_fingerprint(e) in new_fps else ""
        lines.append(
            f"## {i}. {e.title}{new_badge}\n"
            f"- **Source:** {e.source}\n"
            f"- **Date:** {e.date.strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"- **Severity:** {e.severity}\n"
            f"- **CVEs:** {cves}\n"
            f"- **Description:** {e.description}\n"
            f"- **URL:** [{e.url}]({e.url})\n"
        )
    return "\n".join(lines)


# Section heading text → CSS class for border-bottom color coding
_SECTION_CLASS_MAP = {
    "Critical / Action Required": "section-critical",
    "High Relevance": "section-high",
}


def _post_process_html(body_html: str) -> str:
    """Open all links in a new tab, stamp CSS classes onto section headings,
    and convert [NEW] markers into badge HTML."""
    body_html = re.sub(
        r"<a href=",
        '<a target="_blank" rel="noopener noreferrer" href=',
        body_html,
    )
    for heading_text, css_class in _SECTION_CLASS_MAP.items():
        body_html = body_html.replace(
            f"<h2>{heading_text}</h2>",
            f'<h2 class="{css_class}">{heading_text}</h2>',
        )
    body_html = body_html.replace(
        "[NEW]",
        '<span class="badge-new">NEW</span>',
    )
    return body_html


def _new_items_callout_html(new_entries: list[ThreatEntry]) -> str:
    """Build a deterministic 'new since last run' callout box for the HTML report."""
    if not new_entries:
        return ""
    items_html = "".join(
        f"<li><strong>{html.escape(e.title)}</strong> "
        f'(<a href="{html.escape(e.url)}" target="_blank" rel="noopener noreferrer">'
        f"{html.escape(e.source)}</a>)</li>"
        for e in new_entries
    )
    count = len(new_entries)
    label = f"{count} new item{'s' if count != 1 else ''} since last run"
    return (
        f'<div class="new-items-callout">'
        f'<div class="callout-title">{label}</div>'
        f"<ul>{items_html}</ul>"
        f"</div>"
    )


def _build_profile_footer(org_profile: dict) -> str:
    """Build HTML footer showing org profile context, or empty string."""
    company = org_profile.get("company_name", "")
    industries = org_profile.get("industry", [])
    if not company and not industries:
        return ""

    parts = []
    if company:
        parts.append(f"Tailored for <strong>{html.escape(company)}</strong>")
    if industries:
        parts.append(f"Industry: {html.escape(', '.join(industries))}")

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
@click.option("--list-sources", is_flag=True, help="List all available sources and exit")
@click.option(
    "--diff",
    "diff_flag",
    is_flag=True,
    default=False,
    help="Enable [NEW] badges for this run, regardless of config",
)
@click.option(
    "--no-diff",
    "no_diff_flag",
    is_flag=True,
    default=False,
    help="Disable [NEW] badges for this run, regardless of config",
)
@click.pass_context
def main(ctx: click.Context, config_path: str, hours: int | None, dry_run: bool, verbose: bool, output_format: str, list_sources: bool, diff_flag: bool, no_diff_flag: bool) -> None:
    """threat-brief — Daily threat intelligence briefing generator."""
    # If a subcommand was invoked, store config_path for it and return
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path

    if ctx.invoked_subcommand is not None:
        return

    _setup_logging(verbose)

    if list_sources:
        config = _load_config(config_path)
        sources_cfg = config.get("sources", {})
        click.echo("Available sources:\n")
        for src in SOURCE_REGISTRY:
            cfg = sources_cfg.get(src.key, {})
            enabled = _is_source_enabled(cfg)
            status = "enabled" if enabled else "disabled"
            marker = "+" if enabled else "-"
            click.echo(f"  [{marker}] {src.name} ({src.key})")
            click.echo(f"      {src.description}")
            click.echo(f"      Status: {status}")
            click.echo()
        click.echo("Toggle sources in config.yaml under sources.<key>.enabled")
        return

    if diff_flag and no_diff_flag:
        raise click.UsageError("--diff and --no-diff are mutually exclusive")

    config = _load_config(config_path)
    org_profile = config.get("org_profile", {})
    company_name = org_profile.get("company_name", "")
    lookback = hours if hours is not None else config.get("default_hours", 48)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback)

    # Resolve delta-tracking setting (CLI flags override config)
    settings = config.get("settings", {})
    if diff_flag:
        track_new = True
    elif no_diff_flag:
        track_new = False
    else:
        track_new = settings.get("flag_new_items", True)

    click.echo(f"Threat Brief — lookback: {lookback}h (cutoff: {cutoff.strftime('%Y-%m-%d %H:%M UTC')})")
    if company_name:
        click.echo(f"Organization: {company_name}")
    click.echo("Fetching sources...")

    reports_dir = config.get("reports_dir", "./reports")

    # Load manifest before fetching so full-config sources (e.g. GitHub Advisories)
    # can annotate inline [NEW] CVEs in their descriptions
    manifest = load_manifest(reports_dir)
    entries = _fetch_all(config, cutoff, manifest)

    # Delta tracking — compute new fingerprints
    new_fingerprints = get_new_fingerprints(entries, manifest) if track_new else set()
    new_count = len(new_fingerprints)

    # Build the items label for the report header
    if not track_new:
        new_items_suffix = ""
    elif manifest is None:
        new_items_suffix = " (first run)"
    else:
        new_items_suffix = f" ({new_count} new)"

    # Fetch InfoCon level separately (only when ISC is enabled)
    sources_cfg = config.get("sources", {})
    user_agent = config.get("user_agent", "")
    isc_cfg = sources_cfg.get("isc_sans", {})
    infocon_level = ""
    if _is_source_enabled(isc_cfg):
        infocon_url = isc_cfg.get("infocon_url", "")
        if infocon_url:
            infocon_level = fetch_infocon(infocon_url, user_agent)
            click.echo(f"  [InfoCon] Level: {infocon_level.upper()}")

    click.echo(f"\nTotal items: {len(entries)}{new_items_suffix}")

    if dry_run:
        output = _dry_run_output(entries, new_fingerprints if track_new else None)
    else:
        click.echo("\nGenerating LLM summary...")
        llm_cfg = config.get("llm", {})
        provider = llm_cfg.get("provider", "openai_compatible")
        api_key = llm_cfg.get("api_key", "") or os.environ.get("OPENAI_API_KEY", "")

        # Build source list from enabled sources
        source_names = ", ".join(_get_enabled_sources(config))

        header = (
            f"# Threat Intelligence Briefing\n"
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  \n"
            f"**Window:** Last {lookback} hours  \n"
            f"**Sources:** {source_names}  \n"
            f"**Items analyzed:** {len(entries)}{new_items_suffix}\n\n---\n\n"
        )
        summary = summarize(
            entries,
            endpoint=llm_cfg.get("endpoint", "http://localhost:1234/v1"),
            model=llm_cfg.get("model", "local-model"),
            max_tokens=llm_cfg.get("max_tokens", 4096),
            temperature=llm_cfg.get("temperature", 0.3),
            infocon_level=infocon_level,
            org_profile=org_profile,
            new_fingerprints=new_fingerprints if track_new else None,
            provider=provider,
            api_key=api_key,
        )
        output = header + summary

    # Convert to HTML if requested
    if output_format == "html":
        # Strip raw HTML tags from markdown input to prevent XSS from
        # untrusted feed content, while preserving markdown formatting
        sanitized = re.sub(r"<[^>]+>", "", output)
        body_html = markdown.markdown(sanitized, extensions=["extra", "sane_lists"])
        body_html = _post_process_html(body_html)

        # Inject deterministic new-items callout for LLM summary path.
        # Dry-run injects [NEW] directly into heading text (converted by
        # _post_process_html above), so the callout is only needed here.
        if not dry_run and track_new and new_fingerprints:
            new_entries = [e for e in entries if item_fingerprint(e) in new_fingerprints]
            body_html = body_html + _new_items_callout_html(new_entries)

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
            new_items_suffix=new_items_suffix,
            body=body_html,
            infocon_badge=infocon_badge,
            profile_footer=profile_footer,
        )
        ext = ".html"
    else:
        if not dry_run and track_new and new_fingerprints:
            new_entries = [e for e in entries if item_fingerprint(e) in new_fingerprints]
            titles = ", ".join(e.title for e in new_entries)
            count = len(new_entries)
            label = f"{count} new item{'s' if count != 1 else ''} since last run"
            output = output + f"\n\n> **{label}:** {titles}"
        final_output = output
        ext = ".md"

    # Print to stdout (Markdown version for readability in terminal)
    click.echo("\n" + "=" * 60)
    click.echo(output)

    # Write to file
    filepath = _write_report(final_output, reports_dir, ext=ext)
    click.echo(f"\nReport saved to: {filepath}")

    # Always save manifest so future runs have an accurate baseline
    save_manifest(entries, reports_dir)

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

    # Source enable/disable
    click.echo("\nData Sources (y/n, press Enter to keep current setting):")
    # Read existing config to show current state
    with open(config_path) as f:
        config = yaml.safe_load(f) or {}

    existing_sources = config.get("sources", {})
    source_changes: dict[str, bool] = {}

    for src in SOURCE_REGISTRY:
        current = _is_source_enabled(existing_sources.get(src.key, {}))
        current_str = "Y" if current else "N"
        answer = click.prompt(
            f"  {src.name} — {src.description} [{current_str}]",
            default="", show_default=False,
        ).strip().lower()
        if answer in ("y", "yes"):
            source_changes[src.key] = True
        elif answer in ("n", "no"):
            source_changes[src.key] = False
        # else keep current

    # GitHub Advisories — min_severity follow-up (shown only when source is enabled)
    github_cfg = existing_sources.get("github_advisories", {})
    github_enabled_now = source_changes.get(
        "github_advisories", _is_source_enabled(github_cfg)
    )
    github_min_severity: str | None = None
    if github_enabled_now:
        current_min_sev = github_cfg.get("min_severity", "medium")
        click.echo("\nGitHub Advisories severity filter:")
        sev_answer = click.prompt(
            f"  Minimum severity [critical/high/medium/low] [{current_min_sev}]",
            default="",
            show_default=False,
        ).strip().lower()
        if sev_answer in ("critical", "high", "medium", "low"):
            github_min_severity = sev_answer

    # Delta tracking setting
    existing_settings = config.get("settings", {})
    current_flag = existing_settings.get("flag_new_items", True)
    current_str = "Y" if current_flag else "N"
    click.echo("\nDelta tracking:")
    click.echo(
        "  When enabled, items that didn't appear in your previous briefing\n"
        "  will be marked with a [NEW] badge so you can quickly see what changed."
    )
    flag_answer = click.prompt(
        f"  Tag new items since last run with a NEW badge? [{current_str}]",
        default="",
        show_default=False,
    ).strip().lower()
    if flag_answer in ("y", "yes"):
        flag_new_items: bool | None = True
    elif flag_answer in ("n", "no"):
        flag_new_items = False
    else:
        flag_new_items = None  # keep current

    # LLM provider selection
    existing_llm = config.get("llm", {})
    current_provider = existing_llm.get("provider", "openai_compatible")
    click.echo("\nLLM Provider:")
    click.echo("  openai_compatible — local endpoint (LM Studio, Ollama, etc.)")
    click.echo("  openai            — OpenAI API directly (requires API key)")
    provider_answer = click.prompt(
        f"  Provider [{current_provider}]",
        default="",
        show_default=False,
    ).strip().lower()

    new_provider: str | None = None
    new_api_key: str | None = None
    new_endpoint: str | None = None
    new_model: str | None = None

    if provider_answer in ("openai_compatible", "openai"):
        new_provider = provider_answer

    effective_provider = new_provider or current_provider

    if effective_provider == "openai":
        current_key = existing_llm.get("api_key", "")
        masked = f"...{current_key[-8:]}" if len(current_key) > 8 else ("(set)" if current_key else "(not set)")
        click.echo(
            "\n  Note: Your API key will be stored in config.yaml in plaintext.\n"
            "  Alternatively, set the OPENAI_API_KEY environment variable and\n"
            "  leave the api_key field empty."
        )
        key_answer = click.prompt(
            f"  OpenAI API key [{masked}]",
            default="",
            show_default=False,
        ).strip()
        if key_answer:
            new_api_key = key_answer

        current_model = existing_llm.get("model", "gpt-5-mini")
        model_answer = click.prompt(
            f"  Model [{current_model}]",
            default="",
            show_default=False,
        ).strip()
        if model_answer:
            new_model = model_answer
        elif new_provider == "openai" and current_model == "local-model":
            # Switching to openai with a placeholder model — set a sensible default
            new_model = "gpt-5-mini"
    else:
        current_ep = existing_llm.get("endpoint", "http://localhost:1234/v1")
        ep_answer = click.prompt(
            f"  Local endpoint [{current_ep}]",
            default="",
            show_default=False,
        ).strip()
        if ep_answer:
            new_endpoint = ep_answer

    llm_changed = any(v is not None for v in (new_provider, new_api_key, new_endpoint, new_model))

    if not org_profile and not source_changes and flag_new_items is None and not llm_changed and github_min_severity is None:
        click.echo("\nNo changes. Config unchanged.")
        return

    # Merge into config
    if org_profile:
        config["org_profile"] = org_profile

    if flag_new_items is not None:
        if "settings" not in config:
            config["settings"] = {}
        config["settings"]["flag_new_items"] = flag_new_items

    if source_changes or github_min_severity is not None:
        if "sources" not in config:
            config["sources"] = {}
        for key, enabled in source_changes.items():
            if key not in config["sources"]:
                # Initialize from registry defaults
                registry = get_registry_by_key()
                src = registry[key]
                config["sources"][key] = {"url": src.default_url}
                for extra_key, extra_val in src.extra_config.items():
                    config["sources"][key][extra_key] = extra_val
            config["sources"][key]["enabled"] = enabled
        if github_min_severity is not None:
            if "github_advisories" not in config["sources"]:
                config["sources"]["github_advisories"] = {
                    "url": "https://api.github.com/advisories"
                }
            config["sources"]["github_advisories"]["min_severity"] = github_min_severity

    if llm_changed:
        if "llm" not in config:
            config["llm"] = {}
        if new_provider is not None:
            config["llm"]["provider"] = new_provider
        if new_model is not None:
            config["llm"]["model"] = new_model
        if new_api_key is not None:
            config["llm"]["api_key"] = new_api_key
        if new_endpoint is not None:
            config["llm"]["endpoint"] = new_endpoint

    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    click.echo(f"\nConfiguration saved to {config_path}:")
    if org_profile:
        click.echo(yaml.dump({"org_profile": org_profile}, default_flow_style=False, sort_keys=False))
    if source_changes:
        click.echo("Source changes:")
        for key, enabled in source_changes.items():
            status = "enabled" if enabled else "disabled"
            click.echo(f"  {key}: {status}")


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
