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
