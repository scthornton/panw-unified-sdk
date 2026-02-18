"""Parse WildFire XML API responses.

WildFire returns XML for all endpoints. This module handles parsing into typed
Python objects without external dependencies (uses stdlib ElementTree).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from pan_ai_security.exceptions import WildFireError
from pan_ai_security.wildfire.models import SubmitResult, VerdictResult


def parse_submit_response(xml_text: str) -> SubmitResult:
    """Parse the XML response from /submit/file.

    Expected format:
        <wildfire>
            <upload-file-info>
                <sha256>abc123...</sha256>
                <md5>def456...</md5>
                <filename>test.pdf</filename>
                <filetype>PDF</filetype>
                <size>12345</size>
                <url></url>
            </upload-file-info>
        </wildfire>
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise WildFireError(f"Failed to parse WildFire submit response XML: {e}") from e

    # Check for error response
    error = root.find(".//error-message")
    if error is not None and error.text:
        raise WildFireError(f"WildFire submit error: {error.text}")

    info = root.find(".//upload-file-info")
    if info is None:
        raise WildFireError(
            "WildFire submit response missing upload-file-info element",
            details={"raw_xml": xml_text[:500]},
        )

    return SubmitResult(
        sha256=_get_text(info, "sha256"),
        md5=_get_text(info, "md5"),
        filename=_get_text(info, "filename"),
        file_type=_get_text(info, "filetype"),
        size=int(_get_text(info, "size") or "0"),
        url=_get_text(info, "url"),
    )


def parse_verdict_response(xml_text: str) -> VerdictResult:
    """Parse the XML response from /get/verdict.

    Expected format:
        <wildfire>
            <get-verdict-info>
                <sha256>abc123...</sha256>
                <verdict>0</verdict>
                <md5>def456...</md5>
            </get-verdict-info>
        </wildfire>
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise WildFireError(f"Failed to parse WildFire verdict response XML: {e}") from e

    error = root.find(".//error-message")
    if error is not None and error.text:
        raise WildFireError(f"WildFire verdict error: {error.text}")

    info = root.find(".//get-verdict-info")
    if info is None:
        raise WildFireError(
            "WildFire verdict response missing get-verdict-info element",
            details={"raw_xml": xml_text[:500]},
        )

    verdict_text = _get_text(info, "verdict")
    if not verdict_text:
        raise WildFireError("WildFire verdict response missing verdict value")

    try:
        verdict_code = int(verdict_text)
    except ValueError as e:
        raise WildFireError(f"Invalid WildFire verdict code: {verdict_text}") from e

    return VerdictResult(
        sha256=_get_text(info, "sha256"),
        verdict_code=verdict_code,
        md5=_get_text(info, "md5"),
    )


def _get_text(element: ET.Element, tag: str) -> str:
    """Safely extract text from a child element."""
    child = element.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return ""
