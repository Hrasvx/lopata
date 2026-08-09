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
    # rate_limit is requests/second across the whole scan (None = uncapped)
    "retries": 1,
    "rate_limit": None,
    # http://, https:// and socks5:// (socks5h:// resolves DNS through the proxy)
    "proxy": None,
    "user_agent": None,

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
    "zap_autostart": True,
    "zap_cmd": None,
    "zap_start_timeout": 90,      # seconds to wait for the daemon API to come up

    # Blind XSS out-of-band callbacks
    "xss_blind_listener": False,
    "xss_blind_listen_host": "0.0.0.0",
    "xss_blind_listen_port": 0,   # 0 = ephemeral port
    "xss_blind_callback": None,
    "xss_blind_wait": 0,          # seconds to hold the scan open for late hits

    # Headless (Playwright) auth reuse
    "xss_storage_state": None,
    "xss_storage_state_out": None,

    "retry": {
        "max_attempts": 2,          # total attempts, including the first
        "timeout_multiplier": 2.0,  # attempt N gets base_timeout * mult^(N-1)
        "retry_on": ["timed_out", "failed"],
        "backoff_seconds": 2.0,
        "max_tool_timeout": None,
    },

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


# config key holding each tool's base timeout, used for the ETA fallback
TOOL_TIMEOUT_KEYS = {
    "nmap": "nmap_timeout",
    "nikto": "nikto_timeout",
    "sslscan": "ssl_timeout",
    "whatweb": "whatweb_timeout",
    "subfinder": "subfinder_timeout",
    "httpx": "httpx_timeout",
    "ffuf": "ffuf_timeout",
    "nuclei": "nuclei_timeout",
    "dalfox": "dalfox_timeout",
    "sqlmap": "sqlmap_timeout",
    "arjun": "arjun_timeout",
    "gitleaks": "gitleaks_timeout",
    "zap": "zap_timeout",
}


def tool_base_timeout(cfg: dict, tool: str, default: float = 60.0) -> float:
    key = TOOL_TIMEOUT_KEYS.get(tool)
    try:
        return float(cfg.get(key, default)) if key else float(default)
    except (TypeError, ValueError):
        return float(default)


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
