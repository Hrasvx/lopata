from __future__ import annotations

import os

try:
    import yaml
except ImportError:
    yaml = None

DEFAULTS = {
    "threads": 10,          # async concurrency cap (semaphore size) + tool pools
    "timeout": 10.0,
    "max_pages": 100,
    "verify_tls": True,
    "baseline_threshold": 0.92,
    # HTTP fan-out (async layer). retries mirrors the old urllib3 Retry total;
    # rate_limit is requests/second across the whole scan (None = uncapped, the
    # historical behaviour where concurrency was the only throttle).
    "retries": 1,
    "rate_limit": None,

    # Content discovery
    "crawl_depth": 3,
    "content_discovery": True,
    "extra_paths": [],

    # External tool tuning
    "nmap_fast": True,
    "nmap_vuln": True,
    "nmap_scripts": "vuln",
    "nmap_timeout": 300,
    "nmap_script_timeout": 60,
    "nikto_maxtime": 120,
    "nikto_timeout": 240,
    "ssl_timeout": 180,
    "whatweb_timeout": 90,
    "whatweb_aggression": 1,
    "subfinder_timeout": 120,

    # Additional external tools (all bounded and opt-out via `tools:` below).
    "httpx_timeout": 120,
    "ffuf_timeout": 180,
    "ffuf_wordlist": None,        # path; falls back to a small built-in list
    "ffuf_max_hits": 60,
    "nuclei_timeout": 600,
    "nuclei_severity": "low,medium,high,critical",
    "nuclei_max_urls": 40,
    "dalfox_timeout": 300,
    "dalfox_max_targets": 40,
    "sqlmap_timeout": 300,
    "sqlmap_max_targets": 10,
    "arjun_timeout": 180,
    "arjun_max_urls": 10,
    "gitleaks_timeout": 180,
    "gitleaks_max_js": 30,
    "zap_api": "http://127.0.0.1:8080",
    "zap_api_key": None,
    "zap_active": False,          # passive/spider only unless explicitly enabled
    "zap_timeout": 600,
    # ZAP lifecycle: attach to a running daemon at zap_api if present, else
    # spawn one (when zap_autostart) and tear it down at scan end. zap_cmd
    # overrides binary autodetection (zap.sh / zap / owasp-zap / zaproxy).
    "zap_autostart": True,
    "zap_cmd": None,
    "zap_start_timeout": 90,      # seconds to wait for the daemon API to come up

    # Blind XSS out-of-band callbacks. xss_blind_listener starts a built-in
    # server that mints per-injection tokens and correlates hits into the
    # report; xss_blind_callback is an external callback URL used instead (or
    # advertised in place of the listener's own, e.g. behind a tunnel).
    "xss_blind_listener": False,
    "xss_blind_listen_host": "0.0.0.0",
    "xss_blind_listen_port": 0,   # 0 = ephemeral port
    "xss_blind_callback": None,
    "xss_blind_wait": 0,          # seconds to hold the scan open for late hits

    # Headless (Playwright) auth reuse. The scanner's session cookies are always
    # bridged into the browser for DOM/stored-XSS verification; xss_storage_state
    # imports a Playwright storage_state.json on top, and xss_storage_state_out
    # writes the effective state back out for reuse.
    "xss_storage_state": None,
    "xss_storage_state_out": None,

    "modules": None,

    "tools": {
        "nmap": True,
        "nikto": True,
        "sslscan": True,
        "whatweb": True,
        "subfinder": True,
        "httpx": True,
        "ffuf": True,
        "nuclei": True,
        "dalfox": True,
        "sqlmap": True,
        "arjun": True,
        "gitleaks": True,
        "zap": True,
    },
    "auth": {"headers": [], "cookie": None},
}


def load_config(path: str | None) -> dict:
    cfg = _deep_copy(DEFAULTS)
    if not path:
        return cfg
    if yaml is None:
        raise RuntimeError("PyYAML is required for --config but is not installed")
    if not os.path.exists(path):
        raise FileNotFoundError(f"config file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh) or {}
    return _merge(cfg, loaded)


def _deep_copy(obj):
    if isinstance(obj, dict):
        return {k: _deep_copy(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return list(obj)
    return obj


def _merge(base: dict, over: dict) -> dict:
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = _merge(base[k], v)
        else:
            base[k] = v
    return base
