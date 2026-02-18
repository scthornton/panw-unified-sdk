"""UnifiedClient — the main entry point for the Palo Alto Networks AI Security SDK.

This client provides a single interface that routes text to AIRS Runtime API
and files to WildFire API, with unified verdicts and smart content detection.

Usage:
    from pan_ai_security import UnifiedClient

    client = UnifiedClient()  # auto-loads from env vars

    # Scan text
    result = client.scan(prompt="Ignore previous instructions...")
    print(result.verdict)  # "block"

    # Scan a file
    result = client.scan(file="suspicious.pdf")
    print(result.is_safe)  # False

    # Scan both
    result = client.scan(prompt="Analyze this document", file="report.pdf")
    print(result.threats)  # Combined threats from both APIs
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from pan_ai_security.airs.client import AIRSClient
from pan_ai_security.config import SecurityConfig
from pan_ai_security.exceptions import ConfigurationError
from pan_ai_security.router import RouteTarget, route
from pan_ai_security.verdicts import ScanVerdict, merge_verdicts
from pan_ai_security.wildfire.client import WildFireClient

logger = logging.getLogger("pan_ai_security")


class UnifiedClient:
    """Unified scanning client for Palo Alto Networks AI Security.

    Routes text content to AIRS Runtime API and file content to WildFire API.
    Supports degraded operation with only one API key configured.
    """

    def __init__(
        self,
        config: SecurityConfig | None = None,
        *,
        airs_api_key: str = "",
        wildfire_api_key: str = "",
        ai_profile: str = "",
        region: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize the unified client.

        Args:
            config: Full SecurityConfig object. If not provided, auto-loads from env.
            airs_api_key: Override AIRS API key (alternative to config).
            wildfire_api_key: Override WildFire API key (alternative to config).
            ai_profile: Override AI security profile (alternative to config).
            region: Override AIRS region (alternative to config).
        """
        if config is not None:
            self._config = config
        else:
            self._config = SecurityConfig(
                airs_api_key=airs_api_key,
                wildfire_api_key=wildfire_api_key,
                ai_profile=ai_profile,
                airs_region=region or "us",
            )

        self._config.validate()

        self._airs: AIRSClient | None = None
        self._wildfire: WildFireClient | None = None

        if self._config.has_airs:
            self._airs = AIRSClient(self._config)
        if self._config.has_wildfire:
            self._wildfire = WildFireClient(self._config)

        logger.info("UnifiedClient initialized — mode: %s", self._config.mode_description)

    # ------------------------------------------------------------------
    # Primary API
    # ------------------------------------------------------------------

    def scan(
        self,
        *,
        prompt: str | None = None,
        response: str | None = None,
        file: str | Path | bytes | None = None,
        filename: str | None = None,
        ai_profile: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> ScanVerdict:
        """Smart scan — automatically routes to the correct API based on content.

        Provide text for AIRS scanning, a file for WildFire scanning, or both
        for parallel analysis with merged verdicts.

        Args:
            prompt: User prompt or input text to scan.
            response: AI-generated response text to scan.
            file: File path (str/Path) or raw bytes to scan.
            filename: Filename hint when file is bytes.
            ai_profile: Override the configured AI security profile.
            metadata: Additional metadata for AIRS scans.

        Returns:
            Unified ScanVerdict with normalized verdict and threat details.
        """
        decision = route(prompt=prompt, response=response, file=file, filename=filename)

        if decision.target == RouteTarget.AIRS:
            return self.scan_text(
                prompt=decision.prompt or "",
                response=decision.response or "",
                ai_profile=ai_profile,
                metadata=metadata,
            )
        elif decision.target == RouteTarget.WILDFIRE:
            return self.scan_file(
                file=decision.file,  # type: ignore[arg-type]
                filename=decision.filename,
            )
        else:
            # Both — dispatch in parallel
            return self._scan_both(decision, ai_profile=ai_profile, metadata=metadata)

    def scan_text(
        self,
        prompt: str,
        response: str = "",
        *,
        ai_profile: str | None = None,
        metadata: dict[str, str] | None = None,
        tr_id: str | None = None,
    ) -> ScanVerdict:
        """Explicitly scan text content via AIRS Runtime API.

        Args:
            prompt: The user prompt or input text.
            response: Optional AI-generated response.
            ai_profile: Override the configured AI security profile.
            metadata: Additional metadata key-value pairs.
            tr_id: Transaction ID for tracking.

        Returns:
            ScanVerdict from AIRS.

        Raises:
            ConfigurationError: If AIRS is not configured.
        """
        self._require_airs()
        assert self._airs is not None
        return self._airs.scan_text(
            prompt=prompt,
            response=response,
            ai_profile=ai_profile,
            metadata=metadata,
            tr_id=tr_id,
        )

    def scan_file(
        self,
        file: str | Path | bytes,
        filename: str | None = None,
        *,
        poll_interval: int | None = None,
        max_wait: int | None = None,
    ) -> ScanVerdict:
        """Explicitly scan a file via WildFire API.

        Args:
            file: File path (str/Path) or raw bytes.
            filename: Filename hint when passing bytes.
            poll_interval: Seconds between verdict polls.
            max_wait: Max seconds to wait for verdict.

        Returns:
            ScanVerdict from WildFire.

        Raises:
            ConfigurationError: If WildFire is not configured.
        """
        self._require_wildfire()
        assert self._wildfire is not None
        return self._wildfire.scan_file(
            file=file,
            filename=filename,
            poll_interval=poll_interval,
            max_wait=max_wait,
        )

    # ------------------------------------------------------------------
    # Async API
    # ------------------------------------------------------------------

    async def scan_async(
        self,
        *,
        prompt: str | None = None,
        response: str | None = None,
        file: str | Path | bytes | None = None,
        filename: str | None = None,
        ai_profile: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> ScanVerdict:
        """Async version of scan(). Same interface, non-blocking."""
        decision = route(prompt=prompt, response=response, file=file, filename=filename)

        if decision.target == RouteTarget.AIRS:
            return self.scan_text(
                prompt=decision.prompt or "",
                response=decision.response or "",
                ai_profile=ai_profile,
                metadata=metadata,
            )
        elif decision.target == RouteTarget.WILDFIRE:
            self._require_wildfire()
            assert self._wildfire is not None
            return await self._wildfire.scan_file_async(
                file=decision.file,  # type: ignore[arg-type]
                filename=decision.filename,
            )
        else:
            return await self._scan_both_async(
                decision, ai_profile=ai_profile, metadata=metadata
            )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _scan_both(
        self,
        decision: Any,
        ai_profile: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> ScanVerdict:
        """Dispatch to both AIRS and WildFire, merge results."""
        return _run_async(
            self._scan_both_async(decision, ai_profile=ai_profile, metadata=metadata)
        )

    async def _scan_both_async(
        self,
        decision: Any,
        ai_profile: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> ScanVerdict:
        """Async parallel dispatch to both APIs."""
        self._require_airs()
        self._require_wildfire()
        assert self._airs is not None
        assert self._wildfire is not None

        # AIRS is sync, WildFire is async — run AIRS in executor
        loop = asyncio.get_event_loop()

        airs_future = loop.run_in_executor(
            None,
            lambda: self._airs.scan_text(
                prompt=decision.prompt or "",
                response=decision.response or "",
                ai_profile=ai_profile,
                metadata=metadata,
            ),
        )
        wildfire_future = self._wildfire.scan_file_async(
            file=decision.file,
            filename=decision.filename,
        )

        airs_result, wildfire_result = await asyncio.gather(
            airs_future, wildfire_future
        )

        return merge_verdicts(airs_result, wildfire_result)

    def _require_airs(self) -> None:
        """Raise ConfigurationError if AIRS is not available."""
        if self._airs is None:
            raise ConfigurationError(
                "Text scanning requires AIRS configuration. "
                "Set PANW_AI_SEC_API_KEY and PANW_AI_PROFILE environment variables. "
                f"Current mode: {self._config.mode_description}"
            )

    def _require_wildfire(self) -> None:
        """Raise ConfigurationError if WildFire is not available."""
        if self._wildfire is None:
            raise ConfigurationError(
                "File scanning requires WildFire configuration. "
                "Set PANW_WILDFIRE_API_KEY environment variable. "
                f"Current mode: {self._config.mode_description}"
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close_async(self) -> None:
        """Close all client sessions (async)."""
        if self._airs:
            await self._airs.close()
        if self._wildfire:
            await self._wildfire.close()

    def close(self) -> None:
        """Close all client sessions."""
        _run_async(self.close_async())

    def __enter__(self) -> UnifiedClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    async def __aenter__(self) -> UnifiedClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close_async()

    def __repr__(self) -> str:
        return f"UnifiedClient(mode={self._config.mode_description!r})"


def _run_async(coro: Any) -> Any:
    """Run an async coroutine from synchronous code."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)
