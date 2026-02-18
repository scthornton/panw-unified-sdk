"""WildFire API client for file and malware scanning.

WildFire uses a submit-then-poll pattern:
1. Submit a file via multipart/form-data POST
2. Poll for the verdict using the returned SHA-256 hash
3. Convert the integer verdict code into a unified ScanVerdict

Auth is passed as a form parameter (not a header), and responses are XML.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from pathlib import Path
from typing import Any

import aiohttp

from pan_ai_security.config import SecurityConfig
from pan_ai_security.exceptions import ScanTimeoutError, WildFireError
from pan_ai_security.verdicts import ScanVerdict, verdict_from_wildfire
from pan_ai_security.wildfire.models import SubmitResult, VerdictResult
from pan_ai_security.wildfire.xml_parser import parse_submit_response, parse_verdict_response

logger = logging.getLogger("pan_ai_security.wildfire")


class WildFireClient:
    """Client for the Palo Alto Networks WildFire API.

    Handles file submission, verdict polling, and response normalization.
    """

    def __init__(self, config: SecurityConfig) -> None:
        self._config = config
        self._base_url = config.wildfire_base_url.rstrip("/")
        self._api_key = config.wildfire_api_key
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self._config.wildfire_submit_timeout)
            )
        return self._session

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def submit_file_async(
        self,
        file: str | Path | bytes,
        filename: str | None = None,
    ) -> SubmitResult:
        """Submit a file to WildFire for analysis.

        Args:
            file: File path, Path object, or raw bytes.
            filename: Optional filename override (required when passing bytes).

        Returns:
            SubmitResult with SHA-256 hash and metadata.
        """
        session = await self._get_session()
        data = aiohttp.FormData()
        data.add_field("apikey", self._api_key)

        if isinstance(file, (str, Path)):
            file_path = Path(file)
            if not file_path.exists():
                raise WildFireError(f"File not found: {file_path}")
            if not file_path.is_file():
                raise WildFireError(f"Not a file: {file_path}")
            file_bytes = file_path.read_bytes()
            resolved_filename = filename or file_path.name
        elif isinstance(file, bytes):
            file_bytes = file
            resolved_filename = filename or "upload"
        else:
            raise WildFireError(f"Unsupported file type: {type(file)}")

        data.add_field(
            "file",
            file_bytes,
            filename=resolved_filename,
            content_type="application/octet-stream",
        )

        url = f"{self._base_url}/submit/file"
        logger.info(
            "Submitting file to WildFire: %s (%d bytes)", resolved_filename, len(file_bytes)
        )

        try:
            async with session.post(url, data=data) as resp:
                body = await resp.text()
                if resp.status != 200:
                    raise WildFireError(
                        f"WildFire submit failed with HTTP {resp.status}",
                        status_code=resp.status,
                        details={"response_body": body[:500]},
                    )
                return parse_submit_response(body)
        except aiohttp.ClientError as e:
            raise WildFireError(f"WildFire HTTP error during submit: {e}") from e

    async def get_verdict_async(self, file_hash: str) -> VerdictResult:
        """Get the verdict for a previously submitted file.

        Args:
            file_hash: SHA-256 or MD5 hash of the submitted file.

        Returns:
            VerdictResult with the integer verdict code.
        """
        session = await self._get_session()
        data = aiohttp.FormData()
        data.add_field("apikey", self._api_key)
        data.add_field("hash", file_hash)

        url = f"{self._base_url}/get/verdict"
        logger.debug("Polling WildFire verdict for hash: %s", file_hash[:16])

        try:
            async with session.post(url, data=data) as resp:
                body = await resp.text()
                if resp.status != 200:
                    raise WildFireError(
                        f"WildFire verdict failed with HTTP {resp.status}",
                        status_code=resp.status,
                        details={"response_body": body[:500]},
                    )
                return parse_verdict_response(body)
        except aiohttp.ClientError as e:
            raise WildFireError(f"WildFire HTTP error during verdict: {e}") from e

    async def scan_file_async(
        self,
        file: str | Path | bytes,
        filename: str | None = None,
        poll_interval: int | None = None,
        max_wait: int | None = None,
    ) -> ScanVerdict:
        """Submit a file and poll until a verdict is available.

        This is the high-level method most callers should use. It submits the file,
        polls for the verdict at regular intervals, and returns a unified ScanVerdict.

        Args:
            file: File path, Path object, or raw bytes.
            filename: Optional filename override.
            poll_interval: Seconds between verdict polls (default: config value).
            max_wait: Max seconds to wait for verdict (default: config value).

        Returns:
            Unified ScanVerdict with normalized verdict and threat details.

        Raises:
            ScanTimeoutError: If verdict is still pending after max_wait.
        """
        interval = poll_interval or self._config.wildfire_poll_interval
        timeout = max_wait or self._config.wildfire_max_wait
        start_time = time.monotonic()

        # Submit the file
        submit_result = await self.submit_file_async(file, filename)
        sha256 = submit_result.sha256
        logger.info("File submitted successfully. SHA-256: %s", sha256[:16])

        # Poll for verdict
        while True:
            elapsed = time.monotonic() - start_time
            if elapsed > timeout:
                raise ScanTimeoutError(
                    f"WildFire verdict still pending after {elapsed:.0f}s for {sha256[:16]}",
                    elapsed_seconds=elapsed,
                    details={"sha256": sha256},
                )

            verdict_result = await self.get_verdict_async(sha256)

            if not verdict_result.is_pending:
                duration_ms = int((time.monotonic() - start_time) * 1000)
                logger.info(
                    "WildFire verdict received: code=%d for %s (%.1fs)",
                    verdict_result.verdict_code,
                    sha256[:16],
                    duration_ms / 1000,
                )
                return verdict_from_wildfire(
                    verdict_code=verdict_result.verdict_code,
                    sha256=sha256,
                    raw_response={
                        "submit": submit_result.to_dict(),
                        "verdict": verdict_result.to_dict(),
                    },
                    duration_ms=duration_ms,
                )

            logger.debug("Verdict pending for %s, waiting %ds...", sha256[:16], interval)
            await asyncio.sleep(interval)

    # ------------------------------------------------------------------
    # Sync wrappers
    # ------------------------------------------------------------------

    def submit_file(
        self,
        file: str | Path | bytes,
        filename: str | None = None,
    ) -> SubmitResult:
        """Synchronous wrapper for submit_file_async."""
        return _run_async(self.submit_file_async(file, filename))

    def get_verdict(self, file_hash: str) -> VerdictResult:
        """Synchronous wrapper for get_verdict_async."""
        return _run_async(self.get_verdict_async(file_hash))

    def scan_file(
        self,
        file: str | Path | bytes,
        filename: str | None = None,
        poll_interval: int | None = None,
        max_wait: int | None = None,
    ) -> ScanVerdict:
        """Synchronous wrapper for scan_file_async."""
        return _run_async(
            self.scan_file_async(file, filename, poll_interval, max_wait)
        )

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def hash_file(file: str | Path | bytes) -> str:
        """Compute the SHA-256 hash of a file."""
        if isinstance(file, (str, Path)):
            file_bytes = Path(file).read_bytes()
        elif isinstance(file, bytes):
            file_bytes = file
        else:
            raise WildFireError(f"Cannot hash type: {type(file)}")
        return hashlib.sha256(file_bytes).hexdigest()

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None


def _run_async(coro: Any) -> Any:
    """Run an async coroutine from synchronous code."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already inside an event loop — create a new thread
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)
