"""Read-only context handed to every detector.

Fields that are not available for a scan are None. Top-level dict fields are wrapped in MappingProxyType so a
detector cannot replace keys; nested values are shared with the caller and must be treated as read-only by
convention (detectors copy before changing anything).

`as_of` is the reference time for every time-based signal. In Phase 1 there is no release data yet, so it is
the scan time; release-based detectors (Phase 2+) will set it to the release's upload time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping


def _ro(v):
    return MappingProxyType(v) if isinstance(v, dict) else v


@dataclass(frozen=True)
class DetectorContext:
    as_of: datetime
    as_of_source: str = "scan time"
    data: Mapping[str, Any] | None = None          # repo zip contents (text/py/binaries), when kept
    features: Mapping[str, Any] | None = None      # github_client.fetch_features
    scan: Mapping[str, Any] | None = None          # repo_scan.scan_repo result
    security: Mapping[str, Any] | None = None      # security.assess_security result
    bus_factor: Mapping[str, Any] | None = None    # bus_factor.run_bus_factor_analysis result
    health: Mapping[str, Any] | None = None        # scoring.compute_health_score result
    fragility: Mapping[str, Any] | None = None     # fragility.compute_fragility result
    registry: Mapping[str, Any] | None = None      # registry metadata (Phase 2)
    releases: Any = None                           # release history (Phase 2)
    # Who is being scanned, for name-relatedness checks (credential_exfiltration's related hosts, credential-file
    # owners and SSH client aliases): {"repo": "owner/name" | None, "package": {"ecosystem", "name"} | None}.
    # Set at content-scan time, where features/security are not available yet (since 2026.11.08-10).
    identity: Mapping[str, Any] | None = None
    extra: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    @classmethod
    def build(cls, *, as_of: datetime | None = None, as_of_source: str = "scan time", **kw) -> "DetectorContext":
        return cls(as_of=as_of or datetime.now(timezone.utc), as_of_source=as_of_source,
                   **{k: _ro(v) for k, v in kw.items()})
