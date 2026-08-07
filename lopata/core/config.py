from __future__ import annotations

import os

try:
    import yaml
except ImportError:
    yaml = None

DEFAULTS = {
    "threads": 10,
    "timeout": 10.0,
    "max_pages": 100,
    "verify_tls": True,
    "baseline_threshold": 0.92,

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

    "modules": None,

    "tools": {
        "nmap": True,
        "nikto": True,
        "sslscan": True,
        "whatweb": True,
        "subfinder": True,
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
