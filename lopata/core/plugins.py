"""Plugin discovery — the replacement for the hand-maintained MODULES /
INTEGRATIONS dicts.

Every built-in check and external-tool wrapper declares itself with a
module-level ``register()`` that returns a :class:`Plugin`. The loader finds
them two ways:

* **built-ins** — by walking the ``lopata.modules`` and ``lopata.integrations``
  packages and calling ``register()`` on any submodule that defines it, so a new
  file dropped into either package is picked up with no edit to a central list;
* **third-party** — through the ``lopata.plugins`` entry-point group, so an
  external package can add a check by pointing an entry point at a module whose
  ``register()`` returns a :class:`Plugin` (see the README for the pyproject
  snippet).

A :class:`Plugin` is deliberately shaped so instances are drop-in wherever the
old code expected a plain module object: ``plugin.run(ctx, phase)`` and
``plugin.available(ctx)`` are the same callables the modules always exposed.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import pkgutil
from dataclasses import dataclass
from typing import Callable, Optional, Protocol, runtime_checkable

ENTRY_POINT_GROUP = "lopata.plugins"

# Plugin kinds.
KIND_MODULE = "module"          # pure-Python web check, runs in the web phase
KIND_INTEGRATION = "integration"  # external-tool wrapper, recon or post phase

# Integration phases (modules are implicitly "web").
PHASE_RECON = "recon"
PHASE_WEB = "web"
PHASE_POST = "post"


@dataclass(frozen=True)
class Plugin:
    """A discovered check.

    ``run`` and ``available`` are the callables the module exposes; naming the
    fields to match keeps a Plugin usable anywhere the old duck-typed module
    object was (``plugin.run(ctx, phase)`` / ``plugin.available(ctx)``).
    """

    name: str
    kind: str
    run: Callable
    phase: str = PHASE_WEB
    requires_crawl: bool = False
    order: int = 100
    available: Optional[Callable] = None


@runtime_checkable
class PluginModule(Protocol):
    """The contract a plugin module must satisfy: a ``register()`` returning a
    :class:`Plugin`. Integrations additionally expose ``available(ctx)`` and a
    ``PHASE`` constant, both carried on the returned Plugin."""

    def register(self) -> Plugin: ...


def web_module(name: str, run: Callable, *, requires_crawl: bool = False,
               order: int = 100) -> Plugin:
    """Constructor for a web-check plugin's ``register()``."""
    return Plugin(name=name, kind=KIND_MODULE, run=run, phase=PHASE_WEB,
                  requires_crawl=requires_crawl, order=order)


def integration(name: str, run: Callable, available: Callable, *,
                phase: str = PHASE_RECON, order: int = 100) -> Plugin:
    """Constructor for an external-tool plugin's ``register()``."""
    return Plugin(name=name, kind=KIND_INTEGRATION, run=run,
                  available=available, phase=phase, order=order)


def _register_from_module(mod) -> Optional[Plugin]:
    reg = getattr(mod, "register", None)
    if not callable(reg):
        return None
    try:
        plugin = reg()
    except Exception:
        return None
    return plugin if isinstance(plugin, Plugin) else None


def _walk_package(package_name: str, logger=None) -> list[Plugin]:
    plugins: list[Plugin] = []
    try:
        package = importlib.import_module(package_name)
    except Exception:
        return plugins
    for info in pkgutil.iter_modules(package.__path__):
        if info.name.startswith("_"):
            continue
        full = f"{package_name}.{info.name}"
        try:
            mod = importlib.import_module(full)
        except Exception as exc:
            logger and logger.warning("plugin import failed: %s (%s)", full, exc)
            continue
        plugin = _register_from_module(mod)
        if plugin is not None:
            plugins.append(plugin)
    return plugins


def _entry_point_plugins(logger=None) -> list[Plugin]:
    plugins: list[Plugin] = []
    try:
        eps = importlib.metadata.entry_points()
    except Exception:
        return plugins
    # Python 3.10+ supports select(group=...); 3.9 returns a dict-like.
    if hasattr(eps, "select"):
        selected = eps.select(group=ENTRY_POINT_GROUP)
    else:  # pragma: no cover - Python 3.9
        selected = eps.get(ENTRY_POINT_GROUP, [])
    for ep in selected:
        try:
            mod = ep.load()
        except Exception as exc:
            logger and logger.warning("plugin entry point failed: %s (%s)",
                                      ep.name, exc)
            continue
        plugin = (mod if isinstance(mod, Plugin)
                  else _register_from_module(mod))
        if plugin is not None:
            plugins.append(plugin)
    return plugins


_CACHE: Optional[dict] = None


def discover(logger=None, refresh: bool = False) -> dict:
    """Return ``{"modules": [...], "integrations": [...]}``, each a Plugin list
    sorted by ``order`` then name. Built-ins are found by walking the packages;
    third-party plugins from the ``lopata.plugins`` entry-point group are merged
    on top (a same-named entry-point plugin overrides a built-in)."""
    global _CACHE
    if _CACHE is not None and not refresh:
        return _CACHE

    found: list[Plugin] = []
    found += _walk_package("lopata.modules", logger)
    found += _walk_package("lopata.integrations", logger)
    found += _entry_point_plugins(logger)

    # Later registrations (entry points) win on a name+kind clash.
    merged: dict[tuple, Plugin] = {}
    for plugin in found:
        merged[(plugin.kind, plugin.name)] = plugin

    modules = sorted((p for p in merged.values() if p.kind == KIND_MODULE),
                     key=lambda p: (p.order, p.name))
    integrations = sorted(
        (p for p in merged.values() if p.kind == KIND_INTEGRATION),
        key=lambda p: (p.order, p.name))
    _CACHE = {"modules": modules, "integrations": integrations}
    return _CACHE
