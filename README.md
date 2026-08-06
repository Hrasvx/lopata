# lopata

A CLI defensive web-application vulnerability scanner, written in Python and
built for **Alpine Linux**. lopata does its own web-layer testing (XSS, SQLi,
CSRF, headers, CORS, open redirect, exposed files, cookies, clickjacking,
server misconfig) and orchestrates established external tools for the parts they
already solve well (nmap, nikto, sslyze/testssl.sh, whatweb, subfinder). Every
finding lands in one unified report — PDF and optional JSON — with a live,
colourful console UI while it runs.

> ⚠️ **Authorized testing only.** lopata is for security testing of systems you
> **own** or have **explicit written permission** to test. Unauthorized
> scanning may be illegal and unethical. lopata asks you to confirm
> authorization before every scan and identifies itself honestly in the
> target's logs (`User-Agent: lopata/1.0`). You are responsible for how you use
> it.

---

## Highlights

- **Recon → crawl → test → report** pipeline in a single command.
- **Leverages existing tools** instead of reinventing them, and parses their
  output (nmap XML, nikto JSON, sslyze/testssl JSON, whatweb JSON) into one
  findings format. Missing tools are detected at runtime and skipped with a
  warning — never a crash.
- **Serious false-positive reduction** (see below) — a baseline is learned per
  host and every candidate finding is diffed against it; injection results are
  re-tested before being confirmed.
- **Rich console UI**: colour-coded severities, progress spinners per phase, and
  a live-updating findings tally.
- **Clean PDF report** (executive summary, findings table, per-finding evidence
  + remediation, external-tool versions) plus `--json`.
- **Authenticated scans**, **YAML scan profiles**, **checkpoint/resume**, and
  **file logging**.

---

## Installation (Alpine Linux)

```sh
git clone <your-repo-url> lopata && cd lopata
./install.sh                # add --no-tools to skip the external scanners
lopata --help
```

`install.sh` (run as root, or it will use `doas`/`sudo` for the privileged
steps):

1. installs base packages via `apk` (Python, and the build headers Pillow needs
   for reportlab),
2. installs the optional external tools via `apk` (`nmap`, `nmap-scripts`,
   `nikto`, `subfinder`, `whatweb`) plus `sslyze` via pip,
3. creates a project-local virtualenv and `pip install -e .` into it,
4. drops a launcher at `/usr/local/bin/lopata` so you can run `lopata <target>`
   from anywhere.

### musl / Alpine notes

lopata is deliberately friendly to Alpine's musl libc:

- **No `lxml`.** Crawling uses `beautifulsoup4` with the stdlib `html.parser`,
  so there is no `libxml2`/`libxslt` build to fight.
- **reportlab → Pillow** is the only compiled dependency. `install.sh` pulls in
  `jpeg-dev zlib-dev freetype-dev` so Pillow builds (or uses a musl wheel)
  cleanly.
- **cryptography** (an sslyze dependency) ships musl wheels on modern pip;
  `openssl-dev libffi-dev gcc musl-dev` are installed as a fallback for a source
  build.
- Everything else (`requests`, `rich`, `PyYAML`) is pure Python.

### Manual install

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .
```

---

## External tools (all optional)

lopata detects each with `shutil.which` at runtime; if a tool is absent the
corresponding phase is skipped and noted in the report. Install what you want:

| Tool | Purpose in lopata | Install on Alpine |
|------|-------------------|-------------------|
| **nmap** | port/service discovery, `-sV`, `--script vuln` recon | `apk add nmap nmap-scripts` |
| **nikto** | server misconfig / known-vulnerable files | `apk add nikto` |
| **sslyze** *or* **testssl.sh** | TLS protocol/cipher/cert checks | `pip install sslyze` / `apk add testssl.sh` |
| **whatweb** *or* wappalyzer-cli | tech-stack fingerprint (informs which checks run) | `apk add whatweb` |
| **subfinder** *or* amass | passive subdomain enumeration | `apk add subfinder` |

Custom Python logic is reserved for what these tools don't cover well: XSS/SQLi
payload injection with response diffing, CSRF token checks, cookie flags, CORS
misconfig, and open-redirect detection.

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

Run `lopata --help` for the full flag list. On first run of each scan you are
asked to confirm you are authorized; pass `-y` in automation (you still assert
authorization by doing so — in non-interactive contexts lopata refuses without
it).

### Scan modules (toggle with `--modules`, all on by default)

`crawler` · `headers` · `cookies` · `clickjacking` · `cors` · `exposure`
(directory/sensitive files) · `misconfig` (verbose errors + directory listing)
· `redirect` · `csrf` · `xss` (reflected + stored) · `sqli` (error / boolean /
time-based blind).

TLS/SSL and port/service recon come from the `sslscan` and `nmap` integrations
(`--tools`).

---

## False-positive reduction

This is a first-class concern, not an afterthought:

- **Per-host baseline.** Before testing, lopata fetches a random, certainly-
  absent path to learn the app's *not-found* behaviour (which is often a styled
  `200`, not a real `404`). File/directory-exposure checks and passed-through
  nikto items are dropped when their response is indistinguishable from that
  baseline — so a soft-404 catch-all does **not** produce a wall of false hits.
- **Multi-reference diffing for injection.** A payload response must differ from
  **both** the clean (no-payload) response **and** the app's generic bad-input
  page before it counts. SQLi error signatures are ignored if the same signature
  is already present in the clean/bad-input responses.
- **Similarity scoring, not string equality.** Bodies are normalised (volatile
  tokens, timestamps, numbers collapsed) and compared with `difflib`, against a
  configurable threshold (`baseline_threshold`).
- **Retry before confirming.** Reflected-XSS, boolean-blind and time-based-blind
  SQLi are re-tested 2–3 times; a result only becomes *Confirmed* if it
  reproduces.
- **Confidence levels.** Findings are labelled **Confirmed**, **Firm** (directly
  observed, single-shot) or **Tentative** (a lead for manual review, e.g. an
  external tool's item that lopata could not independently reproduce). Tentative
  leads are reported separately and never inflate the confirmed count.

---

## Output

- **PDF report** (`reportlab`): executive summary with a 0–100 risk score and
  severity counts, a findings overview table (endpoint / type / severity /
  confidence), a per-finding detail section with request/response evidence and
  remediation, and an appendix listing which external tools ran and their
  versions.
- **JSON** (`--json`): the same findings plus discovered URLs, subdomains, tool
  metadata, and a timestamped scan log — for diffing or feeding other tooling.

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
├── install.sh              # Alpine apk + pip + symlink installer
├── requirements.txt
├── pyproject.toml          # console-script entry point: lopata = lopata.cli:main
├── lopata.example.yaml     # sample scan profile
└── lopata/
    ├── cli.py              # argument parsing + scan orchestration
    ├── core/               # shared infrastructure
    │   ├── models.py       #   Finding / Severity / Confidence / ScanContext
    │   ├── http.py         #   session factory, target normalization, auth
    │   ├── baseline.py     #   false-positive engine (baseline + similarity)
    │   ├── config.py       #   YAML profile loading + merge
    │   ├── checkpoint.py   #   scan resume/checkpoint
    │   ├── logging_setup.py
    │   └── ui.py           #   rich console UI
    ├── integrations/       # external-tool wrappers (one file per tool)
    │   ├── nmap.py  nikto.py  sslscan.py  whatweb.py  subfinder.py
    ├── modules/            # custom web-layer checks (one file per vuln class)
    │   ├── crawler.py  headers.py  cookies.py  clickjacking.py  cors.py
    │   ├── exposure.py  misconfig.py  open_redirect.py  csrf.py  xss.py  sqli.py
    └── report/             # pdf.py (reportlab) + json_out.py
```

## Safety & scope

lopata is **detection-oriented**: injection probes are read-only (no stacked
queries, no writes), the stored-XSS check submits a single inert marker, the
open-redirect check never follows the redirect and targets a reserved
`.example` host, and cookie values are redacted in evidence. It is a scanner,
not an exploitation framework. Only ever point it at targets you are authorized
to test.

## License

MIT.
