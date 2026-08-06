<h1 align=center>lopata</h1>
<p align="center"><img width="700" src="lopata.png" alt="description" /></p>
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
  findings format.
- **Clean PDF report** (executive summary, findings table, per-finding evidence
  + remediation, external-tool versions) plus `--json`.
- **Authenticated scans**, **checkpoint/resume**, and
  **file logging**.

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

Run `lopata --help` for the full flag list.

## Output

- **PDF report** (`reportlab`): executive summary with a 0–100 risk score and
  severity counts, findings overview table (endpoint / type / severity /
  confidence), per-finding detail section with request/response evidence and
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
├── install.sh
├── requirements.txt
├── pyproject.toml
├── lopata.example.yaml
└── lopata/
    ├── cli.py
    ├── core/
    │   ├── models.py
    │   ├── http.py
    │   ├── baseline.py
    │   ├── config.py
    │   ├── checkpoint.py
    │   ├── logging_setup.py
    │   └── ui.py
    ├── integrations/
    │   ├── nmap.py  nikto.py  sslscan.py  whatweb.py  subfinder.py
    ├── modules/
    │   ├── crawler.py  headers.py  cookies.py  clickjacking.py  cors.py
    │   ├── exposure.py  misconfig.py  open_redirect.py  csrf.py  xss.py  sqli.py
    └── report/
```

## License

MIT.
