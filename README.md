# threat-brief

CLI tool that generates daily threat intelligence briefings by aggregating data from multiple sources and summarizing them via a local LLM.

![Example HTML briefing output](threat_brief.png)

## Sources

- **CISA KEV** — Known Exploited Vulnerabilities catalog (JSON API)
- **MSRC** — Microsoft Security Response Center (CVRF API v3.0)
- **AWS Security Bulletins** — parsed from web page
- **The Hacker News** — threat intel RSS feed
- **SANS ISC** — Internet Storm Center diary entries (RSS) + InfoCon threat level badge

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Requires a local LLM running an OpenAI-compatible API (e.g., [LM Studio](https://lmstudio.ai/) on `localhost:1234`). Configure the endpoint and model in `config.yaml`.

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

Copy the included plist to the LaunchAgents directory (do **not** symlink into a protected folder):

```bash
cp com.threat-brief.plist ~/Library/LaunchAgents/
```

Edit the plist to replace paths with your own, then load it:

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
├── config.yaml                  # LLM endpoint, model, source URLs
├── threat_brief/
│   ├── cli.py                   # Click CLI entry point
│   ├── models.py                # ThreatEntry dataclass
│   ├── html_template.py         # Dark-themed HTML report template
│   ├── summarizer.py            # LLM integration
│   └── sources/
│       ├── cisa_kev.py
│       ├── msrc.py
│       ├── aws_bulletins.py
│       ├── hackernews.py
│       └── isc.py               # SANS ISC diary + InfoCon
└── reports/                     # Generated briefings (gitignored)
```
