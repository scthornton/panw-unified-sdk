"""AIRS Runtime API client — wraps the official pan-aisecurity SDK.

The AIRS API scans text content (prompts and responses) for threats like
prompt injection, DLP violations, malicious URLs, and toxic content.
This client wraps the official SDK and normalizes responses into ScanVerdict.

The official SDK uses a global configuration singleton that reads credentials
from env vars (PANW_AI_SEC_API_KEY, PANW_AI_SEC_API_ENDPOINT). This client
calls global_configuration.init() to set credentials programmatically.
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
        """Lazy-initialize the AIRS scanner.

        The official SDK uses a global _Configuration singleton. We call
        global_configuration.init() to set the API key and endpoint before
        creating the Scanner instance.
        """
        if self._initialized:
            return self._scanner

        try:
            from aisecurity.configuration import global_configuration
            from aisecurity.scan.inline.scanner import Scanner
        except ImportError as e:
            raise AIRSError(
                "pan-aisecurity SDK is not installed. "
                "Install it with: pip install pan-aisecurity"
            ) from e

        try:
            # Configure the global singleton with our credentials
            global_configuration.init(
                api_key=self._config.airs_api_key,
                api_endpoint=self._config.airs_base_url,
            )
            self._scanner = Scanner()
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
        profile_name = ai_profile or self._config.ai_profile
        transaction_id = tr_id or str(uuid.uuid4())

        try:
            from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
            from aisecurity.scan.models.content import Content
        except ImportError as e:
            raise AIRSError("Failed to import AIRS SDK models") from e

        # Build typed SDK objects
        ai_profile_obj = AiProfile(profile_name=profile_name)
        content_obj = Content(prompt=prompt, response=response if response else None)

        scan_kwargs: dict[str, Any] = {
            "ai_profile": ai_profile_obj,
            "content": content_obj,
            "tr_id": transaction_id,
        }

        # Add metadata if provided
        if metadata:
            try:
                from aisecurity.generated_openapi_client.models.metadata import Metadata

                metadata_obj = Metadata(**metadata)
                scan_kwargs["metadata"] = metadata_obj
            except (ImportError, Exception):
                logger.warning("Could not create Metadata object, skipping metadata")

        start_time = time.monotonic()

        try:
            logger.info(
                "Scanning text via AIRS (profile: %s, tr_id: %s)", profile_name, transaction_id
            )
            result = scanner.sync_scan(**scan_kwargs)
            duration_ms = int((time.monotonic() - start_time) * 1000)
            return self._normalize_response(result, transaction_id, duration_ms)
        except AIRSError:
            raise
        except Exception as e:
            error_type = type(e).__name__
            raise AIRSError(
                f"AIRS scan failed ({error_type}): {e}",
                details={"tr_id": transaction_id, "profile": profile_name},
            ) from e

    def _normalize_response(
        self, result: Any, scan_id: str, duration_ms: int
    ) -> ScanVerdict:
        """Convert AIRS SDK ScanResponse into a unified ScanVerdict.

        The ScanResponse is a pydantic model with:
        - action: "allow" or "block"
        - category: "benign" or "malicious"
        - prompt_detected: PromptDetected (url_cats, dlp, injection, toxic_content, ...)
        - response_detected: ResponseDetected (url_cats, dlp, db_security, ...)
        - scan_id, report_id, tr_id, etc.
        """
        raw = _extract_raw(result)

        action = str(getattr(result, "action", "allow")).lower()
        category_str = str(getattr(result, "category", "benign")).lower()
        result_scan_id = getattr(result, "scan_id", scan_id)

        verdict = Verdict.BLOCK if action == "block" else Verdict.ALLOW
        category = Category.MALICIOUS if category_str == "malicious" else Category.BENIGN

        # Extract threats from prompt_detected and response_detected
        threats = _extract_threats(result)

        return ScanVerdict(
            verdict=verdict,
            category=category,
            confidence=1.0 if threats else (0.9 if verdict == Verdict.ALLOW else 0.95),
            source=Source.AIRS,
            scan_id=result_scan_id,
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
    # ScanResponse is a pydantic model — use model_dump
    if hasattr(result, "model_dump"):
        try:
            return result.model_dump(exclude_none=True)
        except Exception:
            pass
    if hasattr(result, "to_dict"):
        return result.to_dict()  # type: ignore[no-any-return]
    if hasattr(result, "__dict__"):
        return {k: v for k, v in result.__dict__.items() if not k.startswith("_")}
    return {"raw": str(result)}


# Maps PromptDetected / ResponseDetected field names to threat descriptions
_PROMPT_DETECTION_MAP: dict[str, tuple[str, Severity, str]] = {
    "injection": (
        "prompt_injection",
        Severity.CRITICAL,
        "Prompt injection attack detected",
    ),
    "url_cats": (
        "malicious_url",
        Severity.HIGH,
        "Malicious or suspicious URL detected in prompt",
    ),
    "dlp": (
        "dlp_violation",
        Severity.HIGH,
        "Data loss prevention violation in prompt",
    ),
    "toxic_content": (
        "toxic_content",
        Severity.MEDIUM,
        "Toxic or harmful content detected in prompt",
    ),
    "malicious_code": (
        "malicious_code",
        Severity.CRITICAL,
        "Malicious code detected in prompt",
    ),
    "agent": (
        "agent_threat",
        Severity.HIGH,
        "Agent-related threat detected in prompt",
    ),
    "topic_violation": (
        "topic_violation",
        Severity.MEDIUM,
        "Topic policy violation in prompt",
    ),
}

_RESPONSE_DETECTION_MAP: dict[str, tuple[str, Severity, str]] = {
    "url_cats": (
        "malicious_url",
        Severity.HIGH,
        "Malicious or suspicious URL detected in response",
    ),
    "dlp": (
        "dlp_violation",
        Severity.HIGH,
        "Data loss prevention violation in response",
    ),
    "db_security": (
        "db_security",
        Severity.HIGH,
        "Database security threat in response",
    ),
    "toxic_content": (
        "toxic_content",
        Severity.MEDIUM,
        "Toxic or harmful content detected in response",
    ),
    "malicious_code": (
        "malicious_code",
        Severity.CRITICAL,
        "Malicious code detected in response",
    ),
    "agent": (
        "agent_threat",
        Severity.HIGH,
        "Agent-related threat detected in response",
    ),
    "ungrounded": (
        "ungrounded",
        Severity.MEDIUM,
        "Ungrounded or hallucinated content in response",
    ),
    "topic_violation": (
        "topic_violation",
        Severity.MEDIUM,
        "Topic policy violation in response",
    ),
}


def _extract_threats(result: Any) -> list[ThreatDetail]:
    """Extract threats from the ScanResponse's detection sub-objects.

    The ScanResponse has:
    - prompt_detected: PromptDetected with bool fields (injection, dlp, url_cats, ...)
    - response_detected: ResponseDetected with bool fields (dlp, db_security, ...)
    """
    threats: list[ThreatDetail] = []

    # Check prompt detections
    prompt_detected = getattr(result, "prompt_detected", None)
    if prompt_detected is not None:
        for field_name, (threat_type, severity, description) in _PROMPT_DETECTION_MAP.items():
            if getattr(prompt_detected, field_name, None) is True:
                threats.append(
                    ThreatDetail(
                        threat_type=threat_type,
                        severity=severity,
                        description=description,
                        location="prompt",
                    )
                )

    # Check response detections
    response_detected = getattr(result, "response_detected", None)
    if response_detected is not None:
        for field_name, (threat_type, severity, description) in _RESPONSE_DETECTION_MAP.items():
            if getattr(response_detected, field_name, None) is True:
                threats.append(
                    ThreatDetail(
                        threat_type=threat_type,
                        severity=severity,
                        description=description,
                        location="response",
                    )
                )

    return threats
