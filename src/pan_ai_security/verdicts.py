"""Unified verdict models that normalize AIRS and WildFire responses."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """Top-level scan verdict."""

    ALLOW = "allow"
    BLOCK = "block"
    PENDING = "pending"


class Category(str, Enum):
    """Threat category — normalized across both APIs."""

    BENIGN = "benign"
    MALICIOUS = "malicious"
    GRAYWARE = "grayware"
    PHISHING = "phishing"
    C2 = "c2"
    PENDING = "pending"


class Severity(str, Enum):
    """Threat severity level."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Source(str, Enum):
    """Which API produced this verdict."""

    AIRS = "airs"
    WILDFIRE = "wildfire"
    COMBINED = "combined"


@dataclass
class ThreatDetail:
    """A single detected threat within a scan result."""

    threat_type: str
    severity: Severity
    description: str
    location: str = ""  # "prompt", "response", "file"

    def to_dict(self) -> dict[str, str]:
        return {
            "threat_type": self.threat_type,
            "severity": self.severity.value,
            "description": self.description,
            "location": self.location,
        }


@dataclass
class ScanVerdict:
    """Unified scan result that normalizes both AIRS and WildFire responses.

    This is the primary return type for all scan operations. Regardless of whether
    content was scanned by AIRS (text), WildFire (files), or both, you get back
    the same structure with consistent field semantics.
    """

    verdict: Verdict
    category: Category
    confidence: float  # 0.0 to 1.0
    source: Source
    scan_id: str
    threats: list[ThreatDetail] = field(default_factory=list)
    raw_response: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_safe(self) -> bool:
        """True if the content was deemed safe to proceed."""
        return self.verdict == Verdict.ALLOW

    @property
    def is_blocked(self) -> bool:
        """True if the content was blocked as a threat."""
        return self.verdict == Verdict.BLOCK

    @property
    def is_pending(self) -> bool:
        """True if the scan is still in progress (WildFire polling)."""
        return self.verdict == Verdict.PENDING

    @property
    def threat_count(self) -> int:
        return len(self.threats)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "category": self.category.value,
            "confidence": self.confidence,
            "source": self.source.value,
            "scan_id": self.scan_id,
            "threats": [t.to_dict() for t in self.threats],
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat(),
            "is_safe": self.is_safe,
        }


# ---------------------------------------------------------------------------
# WildFire verdict code mapping
# ---------------------------------------------------------------------------

WILDFIRE_VERDICT_MAP: dict[int, tuple[Verdict, Category, str]] = {
    0: (Verdict.ALLOW, Category.BENIGN, "benign"),
    1: (Verdict.BLOCK, Category.MALICIOUS, "malware"),
    2: (Verdict.BLOCK, Category.GRAYWARE, "grayware"),
    4: (Verdict.BLOCK, Category.PHISHING, "phishing"),
    5: (Verdict.BLOCK, Category.C2, "command_and_control"),
    -100: (Verdict.PENDING, Category.PENDING, "pending"),
}


def verdict_from_wildfire(
    verdict_code: int,
    sha256: str,
    raw_response: dict[str, Any] | None = None,
    duration_ms: int = 0,
) -> ScanVerdict:
    """Convert a WildFire integer verdict code into a unified ScanVerdict."""
    mapping = WILDFIRE_VERDICT_MAP.get(verdict_code)
    if mapping is None:
        verdict_val, category_val, threat_type = Verdict.BLOCK, Category.MALICIOUS, "unknown"
    else:
        verdict_val, category_val, threat_type = mapping

    threats: list[ThreatDetail] = []
    if verdict_val == Verdict.BLOCK:
        threats.append(
            ThreatDetail(
                threat_type=threat_type,
                severity=_wildfire_severity(verdict_code),
                description=f"WildFire detected {threat_type} (code={verdict_code})",
                location="file",
            )
        )

    return ScanVerdict(
        verdict=verdict_val,
        category=category_val,
        confidence=1.0 if verdict_code != -100 else 0.0,
        source=Source.WILDFIRE,
        scan_id=sha256,
        threats=threats,
        raw_response=raw_response or {},
        duration_ms=duration_ms,
    )


def _wildfire_severity(code: int) -> Severity:
    """Map WildFire verdict code to severity level."""
    if code in (1, 5):
        return Severity.CRITICAL
    if code == 4:
        return Severity.HIGH
    if code == 2:
        return Severity.MEDIUM
    return Severity.LOW


def merge_verdicts(airs_verdict: ScanVerdict, wildfire_verdict: ScanVerdict) -> ScanVerdict:
    """Merge AIRS and WildFire verdicts into a single combined result.

    The most restrictive verdict wins — if either says "block", the combined
    result is "block". Threats from both sources are concatenated.
    """
    if airs_verdict.is_blocked or wildfire_verdict.is_blocked:
        combined_verdict = Verdict.BLOCK
    elif airs_verdict.is_pending or wildfire_verdict.is_pending:
        combined_verdict = Verdict.PENDING
    else:
        combined_verdict = Verdict.ALLOW

    # Pick the more severe category
    blocked = airs_verdict if airs_verdict.is_blocked else wildfire_verdict
    if combined_verdict == Verdict.BLOCK:
        combined_category = blocked.category
    elif combined_verdict == Verdict.PENDING:
        combined_category = Category.PENDING
    else:
        combined_category = Category.BENIGN

    combined_confidence = max(airs_verdict.confidence, wildfire_verdict.confidence)
    combined_threats = airs_verdict.threats + wildfire_verdict.threats
    combined_duration = airs_verdict.duration_ms + wildfire_verdict.duration_ms

    return ScanVerdict(
        verdict=combined_verdict,
        category=combined_category,
        confidence=combined_confidence,
        source=Source.COMBINED,
        scan_id=f"{airs_verdict.scan_id}+{wildfire_verdict.scan_id}",
        threats=combined_threats,
        raw_response={
            "airs": airs_verdict.raw_response,
            "wildfire": wildfire_verdict.raw_response,
        },
        duration_ms=combined_duration,
    )
