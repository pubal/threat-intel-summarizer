# threat-brief

CLI tool that generates daily threat intelligence briefings by aggregating data from multiple sources and summarizing them via a local LLM (LM Studio, Ollama) or the OpenAI API.

![Example HTML briefing output](threat_brief.png)

## Sources

All sources can be individually enabled or disabled in `config.yaml`. Missing `enabled` flags default to `true` for backward compatibility.

| Source | Description | Type |
|--------|-------------|------|
| **Apple Security** | iOS, macOS, watchOS, tvOS, Safari updates — CVE enrichment from detail pages, actively-exploited detection, same-day grouping | HTML scraping |
| **CISA Advisories** | ICS + cybersecurity alerts with CVEs, CVSS scores, sector tags | RSS feed |
| **CISA KEV** | Known Exploited Vulnerabilities catalog | JSON API |
| **MSRC** | Microsoft Security Response Center updates | CVRF API v3.0 |
| **AWS Bulletins** | AWS Security Bulletins | HTML scraping |
| **The Hacker News** | Cybersecurity news and threat reporting | RSS feed |
| **Krebs on Security** | Investigative cybersecurity journalism | RSS feed |
| **Mandiant** | Google/Mandiant threat intelligence research — APT campaigns, threat actors, malware analysis, exploitation trends | RSS feed |
| **SANS ISC** | Internet Storm Center diary + InfoCon threat level | RSS + API |
| **GitHub Advisories** | GitHub Advisory Database — supply chain vulnerabilities for npm, pip, NuGet, Maven, Go, and more, filtered by org tech stack and aggregated into a single summary item | REST API |

The Apple Security source has two extra config options:

```yaml
sources:
  apple_security:
    enabled: true
    url: "https://support.apple.com/en-us/100100"
    fetch_details: true   # Fetch individual release pages for CVE counts and impact descriptions
    group_by_date: true   # Consolidate same-day releases (iOS + macOS + watchOS etc.) into one item
```

- **`fetch_details: true`** — fetches each release's detail page to extract CVE IDs, component names (WebKit, Kernel, etc.), impact descriptions, and the actively-exploited flag. When a release is flagged as actively exploited, severity is set to `Critical` and the description is prefixed with `ACTIVELY EXPLOITED:`. Set to `false` for faster runs with less data.
- **`group_by_date: true`** — on Apple patch days, iOS, macOS, watchOS, tvOS, and Safari often drop simultaneously. This consolidates them into a single briefing item (e.g. "Apple Security Updates — 2026-03-17") with a merged CVE list, preventing Apple from flooding the report with 6–8 separate entries.

The GitHub Advisories source has two extra config options:

```yaml
sources:
  github_advisories:
    enabled: true
    url: "https://api.github.com/advisories"
    min_severity: "medium"   # Skip low-severity advisories. Options: critical, high, medium, low
    github_token: ""         # Optional — set for 5,000 req/hour vs 60 unauthenticated
```

- **`min_severity`** — filters advisories by severity. Defaults to `medium` (includes medium, high, critical). Set to `high` to skip medium advisories, or `critical` for only the most severe. Configurable via `threat-brief init`.
- **`github_token`** — optional GitHub personal access token for higher rate limits. The unauthenticated limit (60 req/hour) is sufficient for typical daily runs — the source fetches only **newly published** advisories in the lookback window, not re-reviews of existing ones. For very broad queries across all ecosystems or runs shorter than hourly, provide a token or set the `GITHUB_TOKEN` environment variable.

All advisories from this source are **aggregated into a single briefing item** to avoid flooding the report. The item's description lists critical and high advisories individually (package, ecosystem, CVE, one-line summary) and rolls up medium advisories into a count by ecosystem. Advisories that directly match packages named in `tech_stack.applications` or `tech_stack.infrastructure` are flagged with `DIRECT MATCH:`. Ecosystem filtering is automatic based on `tech_stack.languages_and_frameworks` — Python maps to `pip`, JavaScript/TypeScript to `npm`, .NET to `nuget`, etc. If no languages are configured, all ecosystems are fetched.

```yaml
# config.yaml — toggle individual sources
sources:
  cisa_kev:
    enabled: true
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  msrc:
    enabled: false   # disable a source you don't need
    url: "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
  # ...
```

List all sources and their current status:

```bash
threat-brief --list-sources
```

The `--list-sources` output shows `[+]` for enabled and `[-]` for disabled sources. Sources can also be toggled interactively via `threat-brief init`.

When a source is disabled:
- It is skipped during fetching
- It is excluded from the report header's source list
- The InfoCon badge is hidden when SANS ISC is disabled

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp config.yaml.example config.yaml
```

Edit `config.yaml` with your LLM provider, endpoint/model, and API key if using OpenAI. See the [LLM Provider](#llm-provider) section below.

## LLM Provider

Two providers are supported, configured via `llm.provider` in `config.yaml`:

| Provider | Description |
|----------|-------------|
| `openai_compatible` | **Default.** Any local LLM running an OpenAI-compatible API — [LM Studio](https://lmstudio.ai/), Ollama, etc. Set `endpoint` to the server URL (e.g. `http://localhost:1234/v1`). No API key needed. |
| `openai` | OpenAI's API directly. Set `model` to e.g. `gpt-5-mini` and supply an API key. |

```yaml
# Local LLM (default)
llm:
  provider: openai_compatible
  endpoint: "http://localhost:1234/v1"
  model: "local-model"
  max_tokens: 4096
  temperature: 0.3

# OpenAI API
llm:
  provider: openai
  model: "gpt-5-mini"   # must be a valid OpenAI model name
  api_key: "sk-..."     # or set OPENAI_API_KEY env var
  max_tokens: 4096      # sent as max_completion_tokens to the API automatically
```

The `api_key` field can be omitted and the `OPENAI_API_KEY` environment variable used instead to avoid storing credentials in `config.yaml`.

**Compatibility notes for `provider: openai`:**

- **Model name** — must be a valid OpenAI model (e.g. `gpt-5-mini`, `gpt-4o`). The local placeholder `local-model` will cause a 404. `threat-brief init` prompts for the model and defaults to `gpt-5-mini` when switching providers.
- **`max_tokens`** — newer OpenAI models (`gpt-5` and later) require `max_completion_tokens` instead of `max_tokens`. The tool translates this automatically; configure `max_tokens` in `config.yaml` as normal.
- **`temperature`** — newer OpenAI models only support the default temperature and ignore custom values. The `temperature` field is omitted from the API call when using `provider: openai`.

The provider, model, API key, and endpoint can all be configured interactively via `threat-brief init`.

## Organization Profile

The LLM summarization prompt is built dynamically from an optional `org_profile` section in `config.yaml`. This tailors the briefing to your organization's industry and technology stack.

Run the interactive setup wizard to configure it:

```bash
threat-brief init
```

Or add it manually to `config.yaml`. Every field is optional — the tool gracefully degrades with any combination of missing fields:

```yaml
org_profile:
  company_name: "Acme Corp"
  industry:
    - "Financial Services"
    - "FinTech"
  tech_stack:
    operating_systems:
      - "Windows 11"
      - "macOS"
    infrastructure:
      - "Active Directory"
      - "AWS (EC2, S3, Lambda, RDS)"
    applications:
      - "Microsoft 365"
      - "SolarWinds"
    languages_and_frameworks:
      - "Python"
      - ".NET"
    security_tools:
      - "CrowdStrike Falcon"
      - "Splunk"
```

When configured, the LLM will:
- Prioritize items affecting technologies in your stack
- Flag CVEs that specifically name products you use
- Score relevance higher for your industry verticals
- Deprioritize items irrelevant to your environment

When no `org_profile` is configured, the tool produces a general-purpose summary prioritized by severity.

## Delta Tracking — [NEW] Badges

After each run, a manifest is saved to `reports/.last_run.json` containing a fingerprint of every item seen (hash of source + title + CVEs). On the next run, any item not in the previous manifest is tagged as new.

- **HTML reports (LLM summary)** — a cyan callout box is appended at the bottom of the report listing each new item's title and source
- **HTML reports (dry-run / fallback)** — a cyan `NEW` pill badge appears inline next to each new item's heading
- **Markdown output** — a blockquote listing new item titles is appended after the summary
- **Report header** — shows `51 items (7 new)`, `51 items (first run)`, or plain count
- **LLM prompt** — new items are marked `[NEW]` in the input; the system prompt instructs the model to call them out in the TL;DR

The manifest is always written after every successful run regardless of the setting, so toggling the feature on later still produces an accurate diff.

**Configuration:**

```yaml
settings:
  flag_new_items: true   # default — set to false to disable globally
```

**CLI overrides** (apply to a single run only, override config):

```bash
threat-brief --diff      # enable badges for this run
threat-brief --no-diff   # disable badges for this run
```

`--diff` and `--no-diff` are mutually exclusive. The setting can also be toggled via `threat-brief init`.

## Usage

```bash
# Full briefing with LLM summarization
threat-brief

# Preview raw items without LLM
threat-brief --dry-run

# Custom lookback window (default: 48 hours)
threat-brief --hours 168

# Verbose logging
threat-brief -v

# Markdown output instead of HTML
threat-brief --format md

# Custom config file
threat-brief --config /path/to/config.yaml

# List all sources and their enabled/disabled status
threat-brief --list-sources

# Interactive setup (org profile, LLM provider, source toggle, delta tracking)
threat-brief init
```

## Output

Reports are saved to `./reports/` as dated files. The default format is **HTML** with a dark-themed report that opens automatically in your browser. Use `--format md` for plain Markdown.

The LLM-generated briefing includes:

- **TL;DR** — executive summary
- **Critical / Action Required** — items needing immediate response
- **High Relevance** — relevant but not immediately actionable
- **Awareness** — general threat landscape items

The HTML report includes a sticky header with generation metadata and a color-coded **InfoCon badge** reflecting the current SANS ISC threat level.

If the LLM endpoint is unavailable, a fallback report with categorized raw items is generated instead.

## Notifications

After each run, threat-brief can push a formatted [Block Kit](https://api.slack.com/block-kit) notification to a Slack channel summarising Critical (and optionally High/Medium) items.

![Example Slack notification](slack.png)

### Slack setup

1. Go to [api.slack.com/apps](https://api.slack.com/apps) → **Create New App** → **From scratch**
2. Under **Features**, select **Incoming Webhooks** and toggle it on
3. Click **Add New Webhook to Workspace**, select the target channel, and click **Allow**
4. Copy the webhook URL (starts with `https://hooks.slack.com/services/…`)

### Configuration

```yaml
notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/T.../B.../..."  # or set SLACK_WEBHOOK_URL env var
    severity_threshold: "critical"   # critical | high | medium
    include_link_to_report: true
    report_base_url: ""              # e.g. http://localhost:8080 — omit for file:// local path
```

The `webhook_url` can be omitted from `config.yaml` and provided via the `SLACK_WEBHOOK_URL` environment variable instead. This is the recommended approach to avoid storing credentials in the config file.

Run `threat-brief init` to configure Slack interactively.

### Severity threshold

| `severity_threshold` | Items included |
|----------------------|----------------|
| `critical` (default) | Critical only |
| `high` | Critical + High |
| `medium` | Critical + High + Medium |

If no items meet the threshold, no message is sent.

### CLI flag

```bash
threat-brief --no-notify   # skip Slack notification for this run
```

### Report link

When `include_link_to_report: true` (the default), a **View Full Report** button is added to the notification. If `report_base_url` is set, the URL is constructed as `<report_base_url>/reports/<filename>`. Otherwise a `file://` path to the local file is used.

> **Note:** Browsers block navigation from Slack to `file://` URLs for security reasons. The `file://` link is useful for local testing — for team-shared notifications set `report_base_url` to a web-accessible base URL.

### Failure handling

Notification failures never block report generation. The tool retries up to 3 times (delays: 1s, 2s, 4s) then logs an error and continues. Future providers (e.g. Microsoft Teams) may be added as additional keys under `notifications:`.

## Scheduled Runs (macOS)

> **Note:** macOS protects `~/Documents/`, `~/Desktop/`, and `~/Downloads/` with TCC (Transparency, Consent, and Control). Launchd agents cannot access files in these folders without Full Disk Access. If your project lives under a protected folder, create a **separate venv** and place **log files** outside of it to avoid `PermissionError` at runtime.

### 1. Create a venv outside protected folders

```bash
mkdir -p ~/.local/share/threat-brief
python3 -m venv ~/.local/share/threat-brief/venv
~/.local/share/threat-brief/venv/bin/pip install -e /path/to/project
```

### 2. Create a wrapper script

Save to `~/.local/bin/threat-brief-runner.sh`:

```bash
#!/bin/zsh
cd /path/to/project
exec ~/.local/share/threat-brief/venv/bin/threat-brief --config config.yaml
```

```bash
chmod +x ~/.local/bin/threat-brief-runner.sh
```

### 3. Install the launchd plist

Copy the example plist, replace `YOUR_USERNAME` with your macOS username, and install it (do **not** symlink into a protected folder):

```bash
cp com.threat-brief.plist.example ~/Library/LaunchAgents/com.threat-brief.plist
# Edit the file to replace YOUR_USERNAME with your actual username
```

Then load it:

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.threat-brief.plist

# Manual trigger
launchctl start com.threat-brief

# Unload
launchctl bootout gui/$(id -u)/com.threat-brief
```

A macOS notification banner will appear when each run completes, showing the item count and number of critical findings.

## Project Structure

```
├── config.yaml                  # LLM endpoint, model, source URLs, org profile
├── threat_brief/
│   ├── cli.py                   # Click CLI entry point
│   ├── models.py                # ThreatEntry dataclass
│   ├── delta.py                 # Delta tracking — fingerprints and manifest
│   ├── html_template.py         # Dark-themed HTML report template
│   ├── summarizer.py            # LLM integration
│   ├── notifications/
│   │   └── slack.py             # Slack Block Kit webhook notifications
│   └── sources/
│       ├── registry.py          # Source registry — add new sources here
│       ├── apple_security.py
│       ├── cisa_all.py
│       ├── cisa_kev.py
│       ├── msrc.py
│       ├── aws_bulletins.py
│       ├── hackernews.py
│       ├── krebs.py
│       ├── mandiant.py
│       ├── isc.py
│       └── github_advisories.py
└── reports/                     # Generated briefings (gitignored)
```

## Adding a New Source

1. Create a fetcher in `threat_brief/sources/` (e.g. `my_source.py`) with a function matching the signature `fetch_my_source(url: str, cutoff: datetime) -> list[ThreatEntry]`
2. Add a `SourceInfo` entry to the `SOURCE_REGISTRY` list in `threat_brief/sources/registry.py`
3. Add the source config to `config.yaml` and `config.yaml.example`

No changes to the main pipeline logic are needed — the registry drives fetching, `--list-sources`, the init wizard, and the report header automatically.
