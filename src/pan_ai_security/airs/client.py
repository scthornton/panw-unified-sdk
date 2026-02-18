"""AIRS Runtime API client — wraps the official pan-aisecurity SDK.

The AIRS API scans text content (prompts and responses) for threats like
prompt injection, DLP violations, malicious URLs, and toxic content.
This client wraps the official SDK and normalizes responses into ScanVerdict.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from pan_ai_security.config import SecurityConfig
from pan_ai_security.exceptions import AIRSError
from pan_ai_security.verdicts import (
    Category,
    ScanVerdict,
    Severity,
    Source,
    ThreatDetail,
    Verdict,
)

logger = logging.getLogger("pan_ai_security.airs")


class AIRSClient:
    """Client for the Palo Alto Networks AIRS Runtime API.

    Wraps the official pan-aisecurity SDK to provide text scanning
    with unified ScanVerdict responses.
    """

    def __init__(self, config: SecurityConfig) -> None:
        self._config = config
        self._scanner: Any = None
        self._initialized = False

    def _ensure_scanner(self) -> Any:
        """Lazy-initialize the AIRS scanner."""
        if self._initialized:
            return self._scanner

        try:
            from aisecurity.scan.inline.scanner import Scanner
        except ImportError as e:
            raise AIRSError(
                "pan-aisecurity SDK is not installed. "
                "Install it with: pip install pan-aisecurity"
            ) from e

        try:
            self._scanner = Scanner(
                api_key=self._config.airs_api_key,
                api_url=self._config.airs_base_url,
            )
            self._initialized = True
            logger.info("AIRS scanner initialized (region: %s)", self._config.airs_region)
            return self._scanner
        except Exception as e:
            raise AIRSError(f"Failed to initialize AIRS scanner: {e}") from e

    def scan_text(
        self,
        prompt: str,
        response: str = "",
        ai_profile: str | None = None,
        metadata: dict[str, str] | None = None,
        tr_id: str | None = None,
    ) -> ScanVerdict:
        """Scan text content (prompt and optional response) via AIRS.

        Args:
            prompt: The user prompt or input text to scan.
            response: Optional AI-generated response text to scan.
            ai_profile: Override the configured AI security profile.
            metadata: Additional metadata key-value pairs.
            tr_id: Transaction ID for tracking.

        Returns:
            Unified ScanVerdict with normalized verdict and threat details.
        """
        scanner = self._ensure_scanner()
        profile = ai_profile or self._config.ai_profile
        transaction_id = tr_id or str(uuid.uuid4())

        scan_kwargs: dict[str, Any] = {
            "ai_profile": profile,
            "content": {"prompt": prompt},
            "tr_id": transaction_id,
        }
        if response:
            scan_kwargs["content"]["response"] = response
        if metadata:
            scan_kwargs["metadata"] = metadata

        start_time = time.monotonic()

        try:
            logger.info("Scanning text via AIRS (profile: %s, tr_id: %s)", profile, transaction_id)
            result = scanner.sync_scan(**scan_kwargs)
            duration_ms = int((time.monotonic() - start_time) * 1000)
            return self._normalize_response(result, transaction_id, duration_ms)
        except AIRSError:
            raise
        except Exception as e:
            error_type = type(e).__name__
            raise AIRSError(
                f"AIRS scan failed ({error_type}): {e}",
                details={"tr_id": transaction_id, "profile": profile},
            ) from e

    def _normalize_response(
        self, result: Any, scan_id: str, duration_ms: int
    ) -> ScanVerdict:
        """Convert AIRS SDK response into a unified ScanVerdict.

        The AIRS SDK returns a response object with attributes like:
        - action: "allow" or "block"
        - category: "benign" or "malicious"
        - Various detection flags (prompt_detected, url_category_detected, etc.)
        """
        raw = _extract_raw(result)
        action = str(getattr(result, "action", raw.get("action", "allow"))).lower()
        category_str = str(
            getattr(result, "category", raw.get("category", "benign"))
        ).lower()

        verdict = Verdict.BLOCK if action == "block" else Verdict.ALLOW
        category = Category.MALICIOUS if category_str == "malicious" else Category.BENIGN

        # Extract individual threat detections
        threats = _extract_threats(result, raw)

        return ScanVerdict(
            verdict=verdict,
            category=category,
            confidence=1.0 if threats else (0.9 if verdict == Verdict.ALLOW else 0.95),
            source=Source.AIRS,
            scan_id=scan_id,
            threats=threats,
            raw_response=raw,
            duration_ms=duration_ms,
        )

    async def close(self) -> None:
        """Cleanup resources."""
        self._scanner = None
        self._initialized = False


def _extract_raw(result: Any) -> dict[str, Any]:
    """Extract a raw dict from the AIRS SDK response object."""
    if isinstance(result, dict):
        return result
    if hasattr(result, "to_dict"):
        return result.to_dict()  # type: ignore[no-any-return]
    if hasattr(result, "__dict__"):
        return {k: v for k, v in result.__dict__.items() if not k.startswith("_")}
    return {"raw": str(result)}


# Map AIRS detection flag names to human-readable threat types
_AIRS_DETECTION_MAP: dict[str, tuple[str, Severity, str]] = {
    "prompt_detected": (
        "prompt_injection",
        Severity.CRITICAL,
        "Prompt injection attack detected",
    ),
    "url_category_detected": (
        "malicious_url",
        Severity.HIGH,
        "Malicious or suspicious URL detected",
    ),
    "dlp_detected": (
        "dlp_violation",
        Severity.HIGH,
        "Data loss prevention violation detected",
    ),
    "injection_detected": (
        "injection",
        Severity.CRITICAL,
        "Injection attack detected",
    ),
    "malware_detected": (
        "malware",
        Severity.CRITICAL,
        "Malware content detected in text",
    ),
    "toxicity_detected": (
        "toxic_content",
        Severity.MEDIUM,
        "Toxic or harmful content detected",
    ),
}


def _extract_threats(result: Any, raw: dict[str, Any]) -> list[ThreatDetail]:
    """Extract individual threats from AIRS detection flags."""
    threats: list[ThreatDetail] = []
    for flag_name, (threat_type, severity, description) in _AIRS_DETECTION_MAP.items():
        detected = getattr(result, flag_name, raw.get(flag_name, False))
        if detected:
            threats.append(
                ThreatDetail(
                    threat_type=threat_type,
                    severity=severity,
                    description=description,
                    location="prompt",
                )
            )
    return threats
