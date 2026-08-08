"""External-tool integrations.

Discovered by walking this package (and the ``lopata.plugins`` entry-point group)
via ``lopata.core.plugins`` rather than a hardcoded list. ``INTEGRATIONS`` is a
backward-compatible view ``name -> plugin``; the plugin exposes ``available(ctx)``
and ``run(ctx, phase)``, and carries its ``phase`` (recon runs before the crawl,
post consumes the discovered surface).
"""

from ..core.plugins import discover

RECON_PHASE = "recon"
POST_PHASE = "post"

INTEGRATIONS = {p.name: p for p in discover()["integrations"]}


def phase_of(name: str) -> str:
    """Which scan phase an integration runs in (default: recon)."""
    plugin = INTEGRATIONS.get(name)
    return plugin.phase if plugin else RECON_PHASE
