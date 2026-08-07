
<p align="center"><img width="700" src="lopata.png" alt="description" /></p>
A CLI defensive web-application security assessment tool, written in Python and
built for **Alpine Linux**. lopata does its own web-layer testing (XSS, SQLi,
CSRF, headers, CORS, open redirect, exposed files, cookies, clickjacking,
server misconfig) and orchestrates established external tools for the parts they
already solve well (nmap, nikto, sslyze/testssl.sh, whatweb, subfinder). Every
finding is exported into a PDF report.

What separates it from a scanner wrapper is what happens *after* the tools run:
every observation is re-checked, classified, correlated across sources, and
scored, so the report reads like an assessment rather than concatenated tool
output. lopata prefers a handful of accurate findings over a long list of
uncertain ones, and it says plainly how sure it is about each.

> ⚠️ **Authorized testing only.** lopata is for security testing of systems you
> **own** or have **explicit written permission** to test. Unauthorized
> scanning may be illegal and unethical. lopata identifies itself honestly in
> the target's logs (`User-Agent: lopata/1.0`). You are responsible for how you
> use it.

---

## Highlights

- **Recon → crawl → test → correlate → report** pipeline in a single command.
- **Interprets tool output rather than forwarding it.** An NSE script that says
  `NOT VULNERABLE` becomes a *passed check*, not a finding; a CVE matched
  against a version banner is a Low-confidence patch-review lead, never a High.
- **Findings are typed**, not all called vulnerabilities: Confirmed
  Vulnerability, Potential Vulnerability, Misconfiguration, Security Exposure,
  Service Inventory, Informational. An open SSH port is an exposure; a
  reproduced SQL injection is a vulnerability.
- **Severity is calculated, not inherited** — from impact, exploitability,
  authentication requirement, network exposure and confirmation level — and the
  report shows the reasoning for every rating.
- **Correlation pass** merges duplicate observations, raises confidence when
  independent sources agree, lowers it when a single tool is the only voice,
  and groups one issue across many URLs into one finding.
- **Category security scores** (TLS, HTTP Security, Attack Surface, Patch
  Management, Web Application Security, Configuration) with a weighted overall.
- **Authenticated scans**, **checkpoint/resume**, **report filtering**, and
  **file logging**.

---

## How findings are graded

Every finding carries a **confidence** level that reflects the evidence behind
it, and confidence caps severity — so an unverified claim can never present
itself as a Critical.

| Confidence | Evidence | Max severity |
|---|---|---|
| **Confirmed** | lopata reproduced the behaviour itself (safe verification) | Critical |
| **High** | Multiple independent sources agree, or a targeted re-test passed | High |
| **Medium** | Strong single-source evidence, not independently verified | Medium |
| **Low** | Banner or version matching only | Low |
| **Informational** | Discovery and inventory data; nothing is being asserted | Info |

Negative results are kept too: the report has a **Checks Passed** section, which
is where "NOT VULNERABLE", "not affected" and "no vulnerabilities found" tool
output ends up instead of being inverted into a finding.

Severity comes from five factors — impact, exploitability, authentication
requirement, network exposure and confidence — plus a published CVSS score when
one applies. A worked example, from the report itself:

```
SQL injection (error-based)                       Critical · Confirmed
Severity rationale
  – Can lead to full compromise of the host or application
  – Publicly accessible from the internet
  – No authentication required
  – Exploitable with a single crafted request
  – Reproduced by lopata during the scan
```

The same engine keeps ratings honest in the other direction: a public MySQL
port is a **Medium** Security Exposure ("reachability, not access"), not a High,
because the engine still requires credentials — while Redis, which has no
authentication by default, is a High.

---

## Installation (Alpine Linux)

```sh
git clone https://github.com/Hrasvx/lopata lopata && cd lopata
./install.sh                # --no-tools to skip the external scanners
lopata --help
```
### Manual install

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .
```

---

## External tools

lopata detects each with `shutil.which` at runtime; if a tool is absent the
corresponding phase is skipped and noted in the report. **`./install.sh`
installs all of these for you** — the table below documents what it does under
the hood, since only some are packaged in the Alpine repos.

| Tool | Purpose in lopata | How install.sh gets it on Alpine 3.24 |
|------|-------------------|----------------------------------------|
| **nmap** | port/service discovery, `-sV`, `--script vuln` recon (bounded by `--host-timeout`/`--script-timeout` so a slow NSE script cannot consume the whole budget) | `apk add nmap nmap-scripts` |
| **nikto** | server misconfig / known-vulnerable files | `apk add nikto` (as `nikto.pl`) **plus its perl deps** `perl-xml-writer perl-json perl-net-ssleay perl-crypt-ssleay perl-io-socket-ssl`, or it errors at runtime |
| **sslyze** *or* **testssl.sh** | TLS protocol/cipher/cert checks | sslyze is `pip install`ed into the venv (primary); testssl.sh is `git clone`d as a fallback — neither is in apk |
| **whatweb** | tech-stack fingerprint (informs which checks run) | **not a RubyGem / not in apk** — `git clone` from GitHub + the Ruby ≥3.4 runtime gems it needs (`getoptlong resolv resolv-replace ipaddr addressable json`) |
| **subfinder** *or* amass | passive subdomain enumeration | **not in apk** — built with `go install` (install.sh adds `go` if missing) |

Tools not in the Alpine repos are symlinked into `/usr/local/bin` after install
so lopata's runtime detection finds them. Custom Python logic is reserved for
what these tools don't cover well: XSS/SQLi payload injection with response
diffing, CSRF token checks, cookie flags, CORS misconfig, and open-redirect
detection.

**What lopata does with their output.** No tool's verdict is copied into the
report as-is:

- **nmap** — open ports become a *service inventory*, never findings. NSE output
  is classified before use: `NOT VULNERABLE` / `not affected` / `patched`
  becomes a passed check; `State: VULNERABLE (Exploitable)` becomes a
  vulnerability; a `vulners` CVE list becomes **one** Low-confidence patch-review
  finding for the service, not one finding per CVE.
- **nikto** — each item is re-requested by lopata and compared against the
  learned soft-404 baseline and the site homepage; anything indistinguishable
  from "not there" is dropped. Surviving items are classified so a missing
  header is a Misconfiguration and an outdated-banner notice is a Low-confidence
  patch lead.
- **sslyze / testssl.sh** — these negotiate real handshakes, so their positive
  results are Confirmed. Their *negative* results become passed checks, so the
  report can show that TLS 1.0 was tested for and rejected.
- **whatweb / wappalyzer** — feeds the technology registry rather than emitting
  a finding. A component seen by both whatweb and lopata's own passive
  fingerprinting is promoted to High confidence.

---

## Usage

```sh
lopata example.com                                  # full scan, all modules + tools
lopata https://example.com --json -o report.pdf     # PDF + JSON to a chosen path
lopata example.com --modules headers,cookies,xss    # only these web modules
lopata example.com --no-tools                        # skip external scanners
lopata example.com --tools nmap,sslscan              # only these integrations
lopata example.com --config profile.yaml             # repeatable scan profile
lopata example.com --auth-cookie "session=abc123" \
                   --auth-header "Authorization: Bearer TOKEN"   # authenticated
lopata example.com --resume                          # continue an interrupted scan
lopata example.com --logfile scan.log -v             # verbose logging to a file
```

Run `lopata --help` for the full flag list.

### Filtering the report

```sh
lopata example.com --min-severity medium        # hide Low/Info noise
lopata example.com --min-confidence high        # only well-evidenced findings
lopata example.com --only-vulns                 # vulnerabilities only
lopata example.com --category "TLS,Cookies"     # by category
lopata example.com --no-correlate               # keep every raw observation
```

Filters apply to the report only. Scoring runs first, so hiding findings never
flatters the score.

> Screenshots are not produced: lopata is a pure-HTTP scanner with no browser
> engine, so evidence is captured as request/response pairs, banners and
> verbatim tool output instead.

## Output

- **PDF report** (`reportlab`), in reading order:
  1. Cover — overall score, grade, severity distribution, surface size
  2. Executive summary — narrative verdict, finding types, principal risks
  3. Security score by category, with weights and the largest contributor to each
  4. Technology summary — CMS, framework, server, language, CDN, WAF, JS libs
  5. Attack surface summary — services grouped by function, external vs internal
  6. Recommended remediation order — priority, effort, business impact, quick wins
  7. Findings by severity, and by type/category
  8. Detailed findings — summary, technical detail, why it matters, potential
     impact, **severity rationale**, evidence (request/response), what lopata
     verified, step-by-step remediation, how to verify the fix, references
  9. Checks passed
  10. Appendices — tooling, discovered URLs, client-side routes, and **raw
      scanner output** verbatim
- **JSON** (`--json`): every finding with its type, confidence rank, score area,
  priority, effort and remediation steps, plus category scores, technology and
  service inventories, passed checks, discovered URLs and raw tool output.

---

## Configuration profiles

Copy `lopata.example.yaml`, edit, and pass with `--config`. A profile pins
threads/timeouts, which modules and external tools to run, baseline tuning, and
(optionally) auth. **CLI flags always override the file.** Prefer passing
secrets via `--auth-cookie`/`--auth-header` rather than committing them to a
profile.

---

## Repository layout

```
lopata/
├── install.sh
├── requirements.txt
├── pyproject.toml
├── lopata.example.yaml
└── lopata/
    ├── cli.py
    ├── core/
    │   ├── models.py       # Finding/Technology/Service, severity + confidence enums
    │   ├── severity.py     # severity calculation and its human-readable reasons
    │   ├── knowledge.py    # per-service risk/impact/remediation knowledge base
    │   ├── correlate.py    # dedup, cross-tool corroboration, grouping
    │   ├── scoring.py      # category scores and weighted overall
    │   ├── baseline.py     # soft-404 learning, used to kill false positives
    │   ├── http.py  config.py  checkpoint.py  logging_setup.py  ui.py
    ├── integrations/
    │   ├── nmap.py  nikto.py  sslscan.py  whatweb.py  subfinder.py
    ├── modules/
    │   ├── crawler.py       # robots, sitemaps, JS endpoints, SPA routes, wordlist
    │   ├── fingerprint.py   # passive tech detection (works without whatweb)
    │   ├── attack_surface.py# groups services by function, external vs internal
    │   ├── headers.py  cookies.py  clickjacking.py  cors.py
    │   ├── exposure.py  misconfig.py  open_redirect.py  csrf.py  xss.py  sqli.py
    └── report/
```

