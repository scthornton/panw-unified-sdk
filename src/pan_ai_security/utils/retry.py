"""Exponential backoff retry logic for API calls."""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from typing import TypeVar

logger = logging.getLogger("pan_ai_security.retry")

T = TypeVar("T")


async def retry_async(
    func: Callable[..., Awaitable[T]],
    *args: object,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    jitter: bool = True,
    retryable_exceptions: tuple[type[Exception], ...] = (Exception,),
    **kwargs: object,
) -> T:
    """Retry an async function with exponential backoff.

    Args:
        func: Async function to retry.
        max_retries: Maximum number of retry attempts.
        base_delay: Initial delay in seconds.
        max_delay: Maximum delay between retries.
        jitter: Add random jitter to prevent thundering herd.
        retryable_exceptions: Exception types that trigger a retry.

    Returns:
        The function's return value on success.

    Raises:
        The last exception if all retries are exhausted.
    """
    last_exception: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except retryable_exceptions as e:
            last_exception = e
            if attempt == max_retries:
                logger.warning(
                    "All %d retries exhausted for %s: %s",
                    max_retries,
                    func.__name__,
                    e,
                )
                raise

            delay = min(base_delay * (2**attempt), max_delay)
            if jitter:
                delay = delay * (0.5 + random.random() * 0.5)  # noqa: S311

            logger.info(
                "Retry %d/%d for %s after %.1fs: %s",
                attempt + 1,
                max_retries,
                func.__name__,
                delay,
                e,
            )
            await asyncio.sleep(delay)

    # Should never reach here, but satisfy type checker
    raise last_exception  # type: ignore[misc]
