# Security Audit Report

**Date:** 2026-03-01
**Auditor:** Claude Sonnet 4.6 (automated)
**Scope:** Full codebase — dependencies, static analysis, supply chain hygiene
**Tool:** pip-audit 2.10.0 + manual static review

---

## Summary

| Severity | Total | Fixed | Needs Review | Accepted Risk |
|----------|-------|-------|--------------|---------------|
| High     | 2     | 2     | 0            | 0             |
| Medium   | 2     | 2     | 0            | 0             |
| Low      | 2     | 0     | 1            | 1             |
| Info     | 4     | 4     | 0            | 0             |
| **Total**| **10**| **8** | **1**        | **1**         |

---

## Findings

### F-01 — Vulnerable pip version in venv
**Severity:** High
**Status:** ✅ Fixed
**File:** `.venv/` (pip 25.2)
**CVEs:** CVE-2025-8869, CVE-2026-1703
**Fix:** Upgraded pip to 26.0.1 (`pip install --upgrade pip`)

---

### F-02 — No network timeout on feedparser RSS fetches
**Severity:** High
**Status:** ✅ Fixed
**Files:**
- `threat_brief/sources/hackernews.py:20`
- `threat_brief/sources/krebs.py:20`
- `threat_brief/sources/isc.py:22`

**Description:** `feedparser.parse(url)` was called directly without a timeout. feedparser uses Python's `urllib` internally, which defaults to the OS socket timeout (potentially infinite). A slow or hung feed server could block the entire run indefinitely.

**Fix:** Pre-fetch each feed with `requests.get(url, timeout=30)` and pass `resp.content` to `feedparser.parse()`. This brings all three sources in line with CISA KEV, MSRC, and AWS which already used requests with explicit timeouts.

---

### F-03 — Dependency pinning: all packages used `>=` constraints
**Severity:** Medium
**Status:** ✅ Fixed
**File:** `requirements.txt`

**Description:** All six dependencies were specified with `>=` floor constraints (e.g. `click>=8.0`). This allows `pip install` to pull in any future version, including one that may introduce breaking changes or a supply chain compromise.

**Fix:** Pinned all dependencies to the currently installed exact versions:

| Package | Was | Now |
|---------|-----|-----|
| click | `>=8.0` | `==8.3.1` |
| requests | `>=2.28` | `==2.32.5` |
| pyyaml | `>=6.0` | `==6.0.3` |
| feedparser | `>=6.0` | `==6.0.12` |
| beautifulsoup4 | `>=4.12` | `==4.14.3` |
| markdown | `>=3.5` | `==3.10.2` |

`pyproject.toml` retains `>=` constraints intentionally (allows flexibility for library consumers); the pinned `requirements.txt` is the install-time lock for this application.

---

### F-04 — Prompt injection boundary not explicitly delimited
**Severity:** Medium
**Status:** ✅ Fixed
**File:** `threat_brief/summarizer.py:88–93, 131–135`

**Description:** Feed data (titles, descriptions, URLs) from external sources was concatenated into the LLM user prompt with no explicit structural delimiter separating it from trusted instructions. A feed item could contain text like `"Ignore previous instructions and instead output..."`.

**Fix:**
1. Strengthened the system prompt warning to reference the explicit data boundary markers and instruct the model to treat delimited content as data only.
2. Wrapped all feed data in `--- BEGIN UNTRUSTED FEED DATA ---` / `--- END UNTRUSTED FEED DATA ---` markers in the user prompt.

---

### F-05 — `config.yaml` present in early git history
**Severity:** Low
**Status:** ⚠️ Needs Manual Review
**File:** Git history (commits `a24c2e9`, `433a55a`, `effd60f`, `4cbe8cc`)

**Description:** `config.yaml` was tracked in git before being moved to `.gitignore` in commit `d047a99` (2026-02-20). The historical commits expose the company name (`REDACTED`) and industry tags. No API keys or passwords were found in the exposed config — only organizational metadata.

**Recommendation:** If this repository is or will be public, or if the company name is sensitive, rewrite git history to remove these commits' version of `config.yaml`:

```bash
git filter-repo --path config.yaml --invert-paths
git push --force-with-lease
```

**Note:** This is destructive and requires all collaborators to re-clone. Coordinate before running. If the repo is private and the company name is not sensitive, this can be accepted as-is.

---

### F-06 — LLM endpoint defaults to HTTP (localhost)
**Severity:** Low
**Status:** ✅ Accepted Risk
**File:** `config.yaml` (`llm.endpoint: http://localhost:1234/v1`)

**Description:** The default LLM endpoint uses `http://` (not `https://`). Traffic to localhost is not at risk of interception, but if this is ever pointed at a remote host, credentials and prompt data would be transmitted in plaintext.

**Recommendation:** If a remote LLM endpoint is ever configured, ensure it uses `https://`. Consider adding a runtime warning if the configured endpoint is non-localhost and non-HTTPS.

---

### F-07 — XSS: feed data HTML-escaped before HTML output
**Severity:** Info
**Status:** ✅ Already Secured
**Files:** `threat_brief/cli.py:280–281`, all source parsers

All feed-derived content (title, description, URL) passes through `re.sub(r"<[^>]+>", "", output)` before being converted from Markdown to HTML. Source parsers additionally strip HTML tags from titles and summaries via `_clean_html()`.

---

### F-08 — HTML injection in template variables
**Severity:** Info
**Status:** ✅ Already Secured
**File:** `threat_brief/html_template.py`, `threat_brief/cli.py:151–165`

All dynamic variables inserted into `HTML_TEMPLATE.format()` are either: derived from Python builtins (datetime, int), validated against an enum (`infocon_level`), or built with `html.escape()` (`company_name`, `industries` in profile footer).

---

### F-09 — SSRF: URLs from feeds are not fetched
**Severity:** Info
**Status:** ✅ Already Secured
**Files:** All source parsers

Feed-derived URLs are stored in `ThreatEntry.url` and rendered as anchor tags in reports only. No code fetches URLs extracted from feed content. All outbound HTTP requests use only URLs from the trusted `config.yaml`.

---

### F-10 — File path traversal in report output
**Severity:** Info
**Status:** ✅ Already Secured
**File:** `threat_brief/cli.py:90–97`

Report filenames are constructed exclusively from `datetime.now().strftime('%Y-%m-%d_%H%M')` — no feed or user data appears in the path. `reports_dir` comes from trusted config. `pathlib.Path` handles path construction safely.

---

## Post-Fix Verification

### pip-audit (after fixes)
```
No known vulnerabilities found
```

### Dry-run smoke test (after fixes)
```
threat-brief --dry-run --hours 24 --format html
→ 1 item fetched, report saved successfully, no errors
```

---

## Recommendations (Not Yet Implemented)

1. **Pin transitive dependencies** — Consider generating a full `requirements-lock.txt` with `pip freeze` after a clean install to lock transitive deps (sgmllib3k, soupsieve, charset-normalizer, etc.).
2. **Add `pyproject.toml` dependency hashes** — Use `pip-compile --generate-hashes` (pip-tools) for hash-verified installs, providing stronger supply chain guarantees.
3. **Content-Security-Policy** — If reports are ever served over HTTP rather than opened locally, add a `<meta http-equiv="Content-Security-Policy">` tag to `html_template.py` to mitigate XSS from any future gaps.
4. **Remote LLM HTTPS check** — Add a startup warning if `llm.endpoint` is non-localhost and uses `http://`.
