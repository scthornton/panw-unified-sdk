"""Smart content router — dispatches to AIRS or WildFire based on content type.

The router inspects what the caller provides and determines which API(s) should
handle the scan. Text goes to AIRS, files go to WildFire, and mixed content
triggers parallel dispatch to both.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from pan_ai_security.exceptions import ContentRouterError
from pan_ai_security.utils.file_detection import is_file_path

logger = logging.getLogger("pan_ai_security.router")


class RouteTarget(str, Enum):
    """Where to send the scan request."""

    AIRS = "airs"
    WILDFIRE = "wildfire"
    BOTH = "both"


@dataclass
class RouteDecision:
    """The router's decision about how to handle a scan request."""

    target: RouteTarget
    prompt: str | None = None
    response: str | None = None
    file: str | Path | bytes | None = None
    filename: str | None = None

    @property
    def has_text(self) -> bool:
        return self.prompt is not None

    @property
    def has_file(self) -> bool:
        return self.file is not None


def route(
    *,
    prompt: str | None = None,
    response: str | None = None,
    file: str | Path | bytes | None = None,
    filename: str | None = None,
) -> RouteDecision:
    """Determine how to route a scan request based on the provided content.

    Args:
        prompt: Text prompt to scan (routes to AIRS).
        response: AI response text to scan (routes to AIRS).
        file: File path, Path, or bytes to scan (routes to WildFire).
        filename: Optional filename for bytes content.

    Returns:
        RouteDecision indicating target API(s) and content.

    Raises:
        ContentRouterError: If no scannable content is provided.
    """
    has_text = bool(prompt or response)
    has_file = file is not None

    # If prompt looks like a file path, auto-detect
    if prompt and not has_file and is_file_path(prompt):
        logger.info("Auto-detected file path in prompt argument: %s", prompt)
        has_file = True
        file = prompt
        prompt = None
        has_text = False

    if not has_text and not has_file:
        raise ContentRouterError(
            "Nothing to scan. Provide at least one of: prompt, response, or file. "
            "Example: client.scan(prompt='Hello') or client.scan(file='doc.pdf')"
        )

    if has_text and has_file:
        target = RouteTarget.BOTH
        logger.info("Mixed content detected — routing to both AIRS and WildFire")
    elif has_text:
        target = RouteTarget.AIRS
        logger.info("Text content — routing to AIRS")
    else:
        target = RouteTarget.WILDFIRE
        logger.info("File content — routing to WildFire")

    return RouteDecision(
        target=target,
        prompt=prompt,
        response=response,
        file=file,
        filename=filename,
    )
