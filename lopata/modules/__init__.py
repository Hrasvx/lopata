"""Web-layer check modules.

The old hand-maintained ``MODULES`` dict is gone: modules are now discovered by
walking this package and calling each submodule's ``register()`` (see
``lopata.core.plugins``). ``MODULES`` is kept as a backward-compatible view —
``name -> (plugin, requires_crawl)`` — because the plugin object exposes
``run(ctx, phase)`` and so is a drop-in for the module object the runner
expected. Execution order is the plugins' ``order`` field.
"""

from ..core.plugins import discover

MODULES = {p.name: (p, p.requires_crawl) for p in discover()["modules"]}
