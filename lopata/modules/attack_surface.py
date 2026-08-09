"""Attack surface analysis.

Consumes the service inventory that the port scanner produced and turns it
into a small number of grouped, explained findings. An open port is never a
finding on its own — the question is what class of service it is, whether that
class belongs on a public interface, and what the owner should do about it.

Grouping is what keeps this readable: SMTP on 465 and 587 is one email-service
finding, not two identical entries.
"""

from __future__ import annotations

from collections import defaultdict

from ..core.knowledge import GROUP_ORDER, SENSITIVE_GROUPS, profile_for
from ..core.models import (AREA_SURFACE, Confidence, Effort, Finding,
                           FindingType, Severity)
from ..core.severity import (AuthRequirement, Exploitability, Exposure, Impact,
                             SeverityFactors, apply)

MODULE_NAME = "attack_surface"
CATEGORY = "Attack Surface"


def run(ctx, phase=None) -> None:
    ctx.modules_run.append(MODULE_NAME)
    phase and phase.done()
    if not ctx.services:
        return

    external = [s for s in ctx.services if not s.internal]
    internal = [s for s in ctx.services if s.internal]

    _inventory(ctx, external, internal)

    grouped: dict[str, list] = defaultdict(list)
    for service in ctx.services:
        grouped[profile_for(service.port, service.name).group].append(service)

    for group in GROUP_ORDER:
        services = grouped.get(group)
        if services:
            _group_finding(ctx, group, services)


def _inventory(ctx, external, internal) -> None:
    lines = []
    for service in sorted(ctx.services, key=lambda s: (s.host, s.port)):
        scope = "internal" if service.internal else "external"
        lines.append(f"  {service.endpoint:<24} {service.name:<14} "
                     f"{service.banner or '-':<40} [{scope}]")

    ctx.add_finding(Finding(
        name=f"Service inventory: {len(ctx.services)} open port(s)",
        severity=Severity.INFO,
        location=ctx.services[0].host if ctx.services else ctx.target,
        description=(
            f"Port scanning found {len(ctx.services)} listening service(s): "
            f"{len(external)} on publicly routable address space and "
            f"{len(internal)} on private address space.\n\n"
            + "\n".join(lines)
        ),
        remediation="Maintain this list as the authoritative record of intended "
                    "exposure.",
        ftype=FindingType.INVENTORY,
        module=MODULE_NAME, category=CATEGORY,
        summary=f"{len(ctx.services)} open port(s): {len(external)} external, "
                f"{len(internal)} internal.",
        risk="Services nobody remembers running are services nobody patches.",
        impact="Informational — this is the surface the rest of the assessment "
               "was carried out against.",
        remediation_steps=[
            "Confirm an owner for every listed service.",
            "Close or firewall anything without a current business need.",
            "Re-run this inventory on a schedule and diff it against the last "
            "known-good list.",
        ],
        verification="Compare against your firewall rules and host inventory.",
        effort=Effort.MODERATE,
        score_area=AREA_SURFACE,
        confidence=Confidence.INFORMATIONAL,
        evidence="\n".join(lines)[:1500],
        sources=["nmap"],
    ))


def _group_finding(ctx, group: str, services: list) -> None:
    profiles = []
    seen_titles = set()
    for service in services:
        prof = profile_for(service.port, service.name)
        if prof.title not in seen_titles:
            seen_titles.add(prof.title)
            profiles.append(prof)

    public_facing = [s for s in services if not s.internal]
    unexpected = [s for s in services
                  if not s.internal
                  and not profile_for(s.port, s.name).public_ok]

    listing = "\n".join(
        f"  {s.endpoint:<24} {s.name:<14} {s.banner or '-'}"
        + ("  [internal address]" if s.internal else "")
        for s in sorted(services, key=lambda s: s.port))

    steps: list[str] = []
    for prof in profiles:
        for step in prof.steps:
            if step not in steps:
                steps.append(step)

    risk = "\n\n".join(prof.risk for prof in profiles if prof.risk)
    impact = "\n\n".join(prof.impact for prof in profiles if prof.impact)
    verification = " ".join(prof.verification for prof in profiles
                            if prof.verification)

    reportable = unexpected or ([s for s in public_facing]
                                if group in SENSITIVE_GROUPS else [])

    if not public_facing:
        ftype = FindingType.INVENTORY
        confidence = Confidence.INFORMATIONAL
        exposure = Exposure.INTERNAL
        headline = f"{group}: {len(services)} service(s) on internal addresses"
    elif unexpected:
        ftype = FindingType.EXPOSURE
        confidence = Confidence.HIGH
        exposure = Exposure.PUBLIC
        headline = (f"{group} exposed to the internet "
                    f"({len(unexpected)} service(s))")
    elif reportable:
        ftype = FindingType.EXPOSURE
        confidence = Confidence.HIGH
        exposure = Exposure.PUBLIC
        headline = (f"{group} reachable from the internet "
                    f"({len(reportable)} service(s))")
    else:
        ftype = FindingType.INVENTORY
        confidence = Confidence.INFORMATIONAL
        exposure = Exposure.PUBLIC
        headline = f"{group}: {len(services)} internet-facing service(s)"

    impact_level = max((profile_for(s.port, s.name).exposure_impact
                        for s in reportable),
                       default=Impact.NEGLIGIBLE)
    exploitability = max((profile_for(s.port, s.name).exploitability
                          for s in reportable),
                         default=Exploitability.NONE)
    auth = min((profile_for(s.port, s.name).auth for s in reportable),
               default=AuthRequirement.NONE)

    finding = Finding(
        name=headline,
        severity=Severity.INFO,
        location=services[0].endpoint,
        description=(
            f"{len(services)} service(s) in the {group} category are listening:\n\n"
            + listing
            + ("\n\nThese are grouped because they share a remediation path; "
               "the steps below cover all of them."
               if len(services) > 1 else "")
            + ("\n\nServices of this kind are normally expected to be publicly "
               "reachable, so this is recorded as inventory rather than as a "
               "problem — but each still needs the hardening described below."
               if ftype is FindingType.INVENTORY and public_facing else "")
            + ("\n\nExposing these is common practice rather than an error, so "
               "this is reported as an exposure to be confirmed as intentional, "
               "not as a defect."
               if reportable and not unexpected else "")
        ),
        remediation=steps[0] if steps else "Review whether this exposure is required.",
        ftype=ftype,
        module=MODULE_NAME, category=CATEGORY,
        summary=headline,
        risk=risk,
        impact=impact,
        remediation_steps=steps,
        verification=verification,
        effort=Effort.EASY,
        score_area=AREA_SURFACE,
        evidence=listing[:1200],
        related_locations=[s.endpoint for s in services[1:]],
        verified_by="nmap completed a TCP connection and service probe",
        confidence=confidence,
        sources=["nmap"],
    )
    apply(finding, SeverityFactors(
        impact=impact_level,
        exploitability=exploitability,
        auth=auth,
        exposure=exposure,
        confidence=confidence,
        notes=([f"{len(unexpected)} service(s) in this group are of a type that "
                "should not be reachable from the internet"] if unexpected
               else ([f"{len(reportable)} administrative or data service(s) are "
                      "reachable from the internet; this may be intended, but it "
                      "should be a deliberate decision"] if reportable else [])),
    ))
    ctx.add_finding(finding)


def register():
    from ..core.plugins import web_module
    return web_module('attack_surface', run, requires_crawl=False, order=20)
