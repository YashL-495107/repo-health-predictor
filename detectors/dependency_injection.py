"""dependency_injection (Integrity) - a dependency ADDED in the latest release that looks like an injection
vehicle (the event-stream / flatmap-stream pattern: a new, young package added to a popular one).

Compares the declared (non-optional) dependencies of release N with release N-1 (releases.py) and profiles each new
one, relative to as_of = the upload time of release N:
  young            first release of the dependency less than YOUNG_DAYS before as_of
  lookalike        name resembles a popular package (blast_radius.confirm_typosquat)
  install hook     the dependency version current at as_of has an install hook (npm registry scripts that are not
                   a known build step; PyPI: Layer 2 on its sdist setup.py, for at most 3 dependencies)
  few dependents   fewer than FEW_DEPENDENTS dependents on deps.dev (current count, NOT as_of; "not available"
                   when deps.dev cannot be reached; used as evidence only, never for the tier)
  removed          the dependency is no longer on the registry (malicious packages are often taken down)
  OSV MAL-         the dependency itself has an OSV malicious-package advisory
Tier: OSV MAL- -> known_malicious (external authority). young + lookalike, or young + install hook -> high_risk.
young alone, lookalike alone, or removed -> review. Otherwise nothing.
Known evasions: injecting through an existing dependency's new version (not a new name), aged "sleeper" packages
published long before use, transitive dependencies (only direct declared dependencies are compared), optional
extras (ignored), install-time payloads fetched by the dependency at runtime.
False-positive sources: projects that split themselves into new sub-packages, brand-new but legitimate helpers,
renamed packages; lookalike names that are legitimate forks.
"""
from detectors.release_analysis import BENIGN_HOOK

from .base import make_result, not_assessed
from .release_common import PILLAR, release_finding, release_gate, version_pair

DETECTOR_ID = "dependency_injection"
YOUNG_DAYS = 30
FEW_DEPENDENTS = 10


def _hooks(prof: dict) -> dict:
    hooks = prof.get("install_hook") or {}
    if prof.get("ecosystem") == "npm":
        hooks = {k: v for k, v in hooks.items() if not BENIGN_HOOK.search(v or "")}
    return hooks


def detect(ctx) -> dict:
    gate, hist = release_gate(ctx, DETECTOR_ID, min_releases=2)
    if gate:
        return gate
    deps = (ctx.releases or {}).get("dependencies")
    if not deps:
        return not_assessed(DETECTOR_ID, PILLAR, "dependency changes not fetched")
    if deps.get("status") != "ok":
        return not_assessed(DETECTOR_ID, PILLAR, deps.get("reason") or "dependency changes not available")
    new, old = hist["releases"][0], hist["releases"][1]
    pair = version_pair(hist, new, old)
    findings, notes = [], []
    for prof in deps.get("profiles") or []:
        name = prof["name"]
        ev = {"type": "registry_field", "dependency": name, "first_release": prof.get("first_release"),
              "age_days_at_release": prof.get("age_days"), "version_at_release": prof.get("version_at_as_of"),
              "dependents": prof.get("dependents"), "dependents_source": prof.get("dependents_status"),
              "lookalike_of": prof.get("lookalike_of"), "install_hook": _hooks(prof) or None,
              "install_hook_source": prof.get("install_hook_source"), "osv_mal": prof.get("osv_mal")}
        if prof.get("osv_mal"):
            findings.append(release_finding(
                DETECTOR_ID, "known_malicious", f"New dependency {name} has an OSV malicious-package advisory",
                f"Added in {new['version']}; OSV lists {', '.join(prof['osv_mal'][:3])}.", [pair, ev],
                fix="Do not install. Remove the dependency."))
            continue
        if not str(prof.get("osv_status", "")).startswith("ran"):
            notes.append(f"{name}: OSV {prof.get('osv_status')}")
        if prof.get("status") == "not_found":
            findings.append(release_finding(
                DETECTOR_ID, "review", f"New dependency {name} is no longer on the registry",
                f"Added in {new['version']}; the package cannot be found now ({prof.get('reason')}). Removed packages are "
                "sometimes malicious ones taken down; it may also never have existed (a typo).", [pair, ev]))
            continue
        if prof.get("status") != "ok":
            notes.append(f"{name}: {prof.get('reason')}")
            continue
        age = prof.get("age_days")
        young = isinstance(age, int) and age < YOUNG_DAYS
        hooks = _hooks(prof)
        look = prof.get("lookalike_of")
        few = isinstance(prof.get("dependents"), int) and prof["dependents"] < FEW_DEPENDENTS
        facts = []
        if young:
            facts.append(f"first published {age} day(s) before {new['version']}")
        if look:
            facts.append(f"name resembles '{look}'")
        if hooks:
            facts.append("has an install hook: " + "; ".join(f"{k}: {v}" for k, v in list(hooks.items())[:2]))
        if few:
            facts.append(f"{prof['dependents']} dependents on deps.dev (current count)")
        elif prof.get("dependents") is None:
            facts.append("dependents count not available")
        if young and (look or hooks):
            tier = "high_risk"
        elif young or look:
            tier = "review"
        else:
            continue
        findings.append(release_finding(
            DETECTOR_ID, tier, f"New dependency {name} in {new['version']}: " + ("young and " + ("lookalike" if look else "with an install hook")
                                                                               if tier == "high_risk" else ("young package" if young else "lookalike name")),
            f"Not a dependency of {old['version']}. " + "; ".join(facts) + ".", [pair, ev],
            fix="Check who published the new dependency and why it was added."))
    if deps.get("not_looked_up"):
        notes.append(f"{len(deps['not_looked_up'])} new dependencies not looked up (limit)")
    return make_result(DETECTOR_ID, PILLAR, "ran", findings, coverage="partial" if notes else "full",
                       coverage_detail="; ".join(notes) or None)
