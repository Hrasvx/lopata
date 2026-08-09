<p align="center"><img width="700" src="lopata.png" alt="description" /></p>

Lopata is a command-line tool that checks websites for security problems. It runs on Alpine Linux and is written in Python.

It does checks for XSS, SQL injection, CSRF, bad headers, CORS issues, open redirects, exposed files, cookie problems, and clickjacking. For everything else, it calls well-known tools like nmap, nikto, sslyze/testssl.sh, whatweb, subfinder, httpx, ffuf, nuclei, dalfox, sqlmap, arjun, gitleaks, and OWASP ZAP.

Every result gets turned into a PDF or a single self-contained HTML report.

⚠️ **Only test sites you own or have written permission to test.** You are responsible for how you use this tool.



## How findings are scored

Every finding has a **confidence** level, and that confidence limits how high its severity can go.

| Confidence | What it means | 
|---|---|
| **Confirmed** | Lopata safely reproduced the issue itself |
| **High** | Two+ tools agree, or a retest confirmed it |
| **Medium** | Strong evidence, but from one source only |
| **Low** | Based only on a version number or banner |
| **Informational** | Just discovery data, no claim being made |

Passed checks are kept in their own section "not vulnerable".

Severity is worked out from five things: impact, how exploitable it is, whether authentication is needed, whether it's reachable from the internet, and confidence + a public CVSS score if one exists.

### When a tool doesn't finish

A scanner that quietly drops a timed-out tool's results can't tell you the difference between "we looked and it was clean" and "we never finished looking". Lopata tracks how every external tool ended — `completed`, `timed_out`, `failed`, or `skipped_missing` — and uses it:

- A finding whose **only** evidence came from a tool that timed out or failed is capped at **Low** confidence (which caps its severity through the normal rule), flagged `incomplete_coverage`, and carries a line saying so: *"Evidence from dalfox, which timed out before completing this target — treat as unverified."*
- A finding **two** sources agree on keeps its confidence even if one of them timed out — the other one finished and still saw it.
- If any tool didn't finish, the report opens with a banner: *"This report may be incomplete — 11 of 13 tools finished (list: dalfox: timed out, zap: skipped missing)."* This is never folded into the score; an unfinished scan is a less trustworthy report, not a worse security posture.
- `--json` carries the same thing as a top-level `scan_completeness` object, plus per-tool `tool_runs`, so CI can gate on coverage instead of guessing.

### Retrying tools that run out of time

Before accepting that gap, lopata gives a timed-out tool another go with a bigger budget — usually the only thing wrong was the timeout:

```yaml
retry:
  max_attempts: 2          # total attempts, including the first
  timeout_multiplier: 2.0  # attempt N runs at base_timeout * multiplier^(N-1)
  retry_on: [timed_out, failed]
  backoff_seconds: 2.0
  max_tool_timeout: null   # e.g. 1800 to never let an attempt exceed 30 min
```

Every attempt is logged: `dalfox: attempt 1/2 timed out after 1800s, retrying with 3600s timeout`. A missing binary is never retried. Retries all finish inside the tool phase, before correlation runs. `--no-retry` restores single-attempt behaviour and `--max-tool-timeout SECONDS` caps how far a timeout may grow. Interrupting a scan mid-retry and resuming it with `--resume` picks up the remaining attempts rather than handing every tool a fresh budget.

---

## Installing on Alpine Linux
just the best distro btw
```sh
git clone https://github.com/Hrasvx/lopata lopata && cd lopata
./install.sh                # add --no-tools to skip external scanners
lopata --help
```

### Manual install

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .
```

---

## External tools it uses

 `./install.sh` installs everything below.

| Tool | What it's used for |
|------|--------------------|
| **nmap** | Finds open ports and running services |
| **nikto** | Checks for server misconfigurations and known bad files |
| **sslyze** / **testssl.sh** | Checks TLS versions, ciphers, and certificates |
| **whatweb** | Detects what tech stack the site uses |
| **subfinder** | Finds subdomains |
| **httpx** | Quickly checks which found URLs are actually live |
| **ffuf** | Discovers hidden pages and files |
| **nuclei** | Matches the site against known CVE templates |
| **dalfox** | A second, independent XSS scanner |
| **sqlmap** | Confirms SQL injection leads found by lopata |
| **arjun** | Finds hidden URL parameters |
| **gitleaks** | Scans site files for leaked secrets |
| **OWASP ZAP** | A second, independent web app scanner |

Tools not available through Alpine's package manager get built or downloaded by `install.sh` and linked so lopata can find them.

**Order of operations:** nmap, nikto, sslyze/testssl, whatweb, subfinder, httpx, and ffuf run first, since they only need the target host. Arjun, nuclei, dalfox, sqlmap, ZAP, and gitleaks run after the crawler, since they need the URLs, forms, and pages it finds. Everything then goes through the same merging step, so results across tools get cross-checked against each other.

---

## XSS checker

Instead of blasting every page with generic payloads, lopata figures out **which characters get through** unescaped, **where** the input lands (HTML, an attribute, JavaScript, a URL, etc.), and builds the **smallest payload that works** for that spot.

It checks for:

- **Reflected XSS** — in URL parameters, form fields, headers, and JSON API bodies, including hidden parameters found by Arjun.
- **Stored XSS** — submits a unique marker through a form, then checks if it shows up unescaped elsewhere.
- **DOM-based XSS** — confirmed using a real (headless) browser, including while logged in, if Playwright is installed.
- **Blind XSS** — plants a unique tracking payload per input and waits for a callback, either from lopata's own built-in listener or an external service you set up.

---

## Usage

```sh
lopata example.com                                  # full scan, all modules + tools
lopata https://example.com --json -o report.pdf     # PDF + JSON to a chosen path
lopata example.com --export html                     # self-contained HTML report
lopata example.com -o report.html                    # format inferred from extension
lopata example.com --export html --json              # HTML + JSON together
lopata example.com --modules headers,cookies,xss    # only these web modules
lopata example.com --no-tools                        # skip external scanners
lopata example.com --tools nmap,dalfox,nuclei        # only these integrations
lopata example.com --config profile.yaml             # repeatable scan profile
lopata example.com --auth-cookie "session=abc123" \
                   --auth-header "Authorization: Bearer TOKEN"   # authenticated
lopata example.com --resume                          # continue an interrupted scan
lopata example.com --logfile scan.log -v             # verbose logging to a file
lopata example.com --no-retry                        # one attempt per tool
lopata example.com --max-tool-timeout 900            # cap retried tool timeouts
```

`--export {pdf,html}` picks the report format (default is `pdf`). Using `-o` with a `.html` file name also switches the format, unless `--export` is set explicitly. `--json` works independently of both.

### Watching a scan

The console keeps everything that changes in one live block that's redrawn in place, so a noisy target can't bury the progress display:

```
╭─ findings ───────────────────────────────────────────────────────────╮
│ CRIT: 1  HIGH: 2  MED: 4  LOW: 6  INFO: 0  TOTAL: 13                 │
╰──────────────────────────────────────────────────────────────────────╯
⠋ verify: nuclei ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 12/19 0:04:12
  [12/19] running nuclei ...  elapsed 2m14s / est. 3m40s  |  scan ETA: ~9m remaining
╭─ latest ─────────────────────────────────────────────────────────────╮
│  CRIT  VULN      SQL injection  (confirmed)  /item?id=3 [param: id]  │
│  HIGH  POSSIBLE  Reflected XSS  /search?q=1 [param: q]               │
│  MED   MISCONFIG Missing Content-Security-Policy  /                  │
│   … 10 earlier finding(s) — all of them are in the report            │
╰──────────────────────────────────────────────────────────────────────╯
                                                       lopata · hrasvx
```

Findings are a rolling window of the most recent few, not a scrolling log — the counters, the final summary and the report hold the full set. Finished phases drop out of the progress block instead of stacking up. Only section rules and notes reach the scrollback.

With `--no-ui`, or when output is piped or redirected, lopata falls back to plain lines — one per finding — which is what CI and `tee` want.

Per-tool estimates come from a rolling average of that tool's last few runs, kept in `~/.cache/lopata/timings.json`. A tool with no history yet falls back to its configured timeout and is labelled `(estimated, no history yet)` rather than pretending to be precise. If a tool goes into a retry with a longer timeout, the ETA widens to match. `--resume` counts phases already done, `--no-tools` shows module timing only, and the live display is console-only — `--logfile` still gets plain, structured lines.

### Filtering the report

```sh
lopata example.com --min-severity medium        # hide Low/Info noise
lopata example.com --min-confidence high        # only well-evidenced findings
lopata example.com --only-vulns                 # vulnerabilities only
lopata example.com --category "TLS,Cookies"     # by category
lopata example.com --no-correlate               # keep every raw observation
```

Filters only affect the report — scoring is done before filtering, so hiding findings never improves the score.

## Configuration profiles

Copy `lopata.example.yaml`, edit it, and run with `--config`. It can set thread/timeout defaults, which modules and tools to run, and (optionally) auth details. **Command-line flags always override the config file.** Prefer `--auth-cookie`/`--auth-header` over putting secrets in the file.

---

## Project layout

```
lopata/
├── install.sh
├── requirements.txt
├── pyproject.toml
├── lopata.example.yaml
└── lopata/
    ├── cli.py
    ├── core/           # data models, severity logic, correlation, scoring, config
    ├── integrations/   # nmap, nikto, whatweb, nuclei, dalfox, sqlmap, zap, etc.
    ├── modules/         # crawler, fingerprinting, headers, cookies, xss, sqli, etc.
    └── report/          # pdf.py  html.py  json_out.py  sarif_out.py
```

## Running the tests

```sh
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```

Covers tool-status tracking and confidence capping, the retry supervisor, every integration's skip path, and the ETA estimator.

## Writing a plugin

Checks and integrations are auto-discovered — just drop a new file into `lopata/modules/` or `lopata/integrations/` with a `register()` function, and lopata finds it.

```python
# lopata/modules/customplugin.py
from ..core.plugins import web_module

MODULE_NAME = "customplugin"

def run(ctx, phase=None):
    ctx.modules_run.append(MODULE_NAME)
    # ... ctx.add_finding(Finding(...)) ...

def register():
    return web_module(MODULE_NAME, run, requires_crawl=True, order=115)
```
