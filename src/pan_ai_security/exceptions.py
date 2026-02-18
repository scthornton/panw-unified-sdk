"""Exception hierarchy for the Palo Alto Networks AI Security SDK."""

from __future__ import annotations


class PanAISecurityError(Exception):
    """Base exception for all SDK errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.details = details or {}


class ConfigurationError(PanAISecurityError):
    """Raised when required configuration is missing or invalid.

    Common causes: missing API keys, invalid region, no .env file.
    """


class AIRSError(PanAISecurityError):
    """Raised when the AIRS Runtime API returns an error.

    Wraps exceptions from the pan-aisecurity SDK and HTTP failures.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details)
        self.status_code = status_code


class WildFireError(PanAISecurityError):
    """Raised when the WildFire API returns an error.

    Covers HTTP failures, XML parsing errors, and invalid responses.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details)
        self.status_code = status_code


class ContentRouterError(PanAISecurityError):
    """Raised when the smart router cannot determine content type or dispatch target."""


class ScanTimeoutError(PanAISecurityError):
    """Raised when a scan operation exceeds the configured timeout.

    Most common with WildFire file scans that require polling.
    """

    def __init__(
        self,
        message: str,
        elapsed_seconds: float = 0.0,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details)
        self.elapsed_seconds = elapsed_seconds
