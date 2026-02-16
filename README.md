# threat-brief

CLI tool that generates daily threat intelligence briefings by aggregating data from multiple sources and summarizing them via a local LLM.

## Sources

- **CISA KEV** — Known Exploited Vulnerabilities catalog (JSON API)
- **MSRC** — Microsoft Security Response Center (CVRF API v3.0)
- **AWS Security Bulletins** — parsed from web page
- **The Hacker News** — threat intel RSS feed

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

# Custom config file
threat-brief --config /path/to/config.yaml
```

## Output

Reports are written to both stdout and a dated Markdown file in `./reports/`. The LLM-generated briefing includes:

- **TL;DR** — executive summary
- **Critical / Action Required** — items needing immediate response
- **High Relevance** — relevant but not immediately actionable
- **Awareness** — general threat landscape items

If the LLM endpoint is unavailable, a fallback report with categorized raw items is generated instead.

## Scheduled Runs (macOS)

Create a launchd plist at `~/Library/LaunchAgents/com.threat-brief.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.threat-brief</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/project/.venv/bin/threat-brief</string>
        <string>--config</string>
        <string>/path/to/project/config.yaml</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/path/to/project</string>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>6</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>/path/to/project/reports/launchd-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/path/to/project/reports/launchd-stderr.log</string>
</dict>
</plist>
```

Replace `/path/to/project` with your actual project directory, then load it:

```bash
launchctl load ~/Library/LaunchAgents/com.threat-brief.plist

# Manual trigger
launchctl start com.threat-brief

# Unload
launchctl unload ~/Library/LaunchAgents/com.threat-brief.plist
```

A macOS notification banner will appear when each run completes, showing the item count and number of critical findings.

## Project Structure

```
├── config.yaml                  # LLM endpoint, model, source URLs
├── threat_brief/
│   ├── cli.py                   # Click CLI entry point
│   ├── models.py                # ThreatEntry dataclass
│   ├── summarizer.py            # LLM integration
│   └── sources/
│       ├── cisa_kev.py
│       ├── msrc.py
│       ├── aws_bulletins.py
│       └── hackernews.py
└── reports/                     # Generated briefings (gitignored)
```
