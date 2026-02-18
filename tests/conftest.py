"""Shared test fixtures for the pan-ai-security test suite."""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

from pan_ai_security.config import SecurityConfig


@pytest.fixture
def airs_only_config() -> SecurityConfig:
    """Config with only AIRS credentials."""
    return SecurityConfig(
        airs_api_key="test-airs-key-12345",
        ai_profile="test-profile",
        airs_region="us",
        _loaded=True,
    )


@pytest.fixture
def wildfire_only_config() -> SecurityConfig:
    """Config with only WildFire credentials."""
    return SecurityConfig(
        wildfire_api_key="test-wildfire-key-12345",
        _loaded=True,
    )


@pytest.fixture
def full_config() -> SecurityConfig:
    """Config with both AIRS and WildFire credentials."""
    return SecurityConfig(
        airs_api_key="test-airs-key-12345",
        ai_profile="test-profile",
        airs_region="us",
        wildfire_api_key="test-wildfire-key-12345",
        _loaded=True,
    )


@pytest.fixture
def empty_config() -> SecurityConfig:
    """Config with no credentials at all."""
    return SecurityConfig(_loaded=True)


# Sample WildFire XML responses
WILDFIRE_SUBMIT_XML = """<?xml version="1.0" encoding="UTF-8"?>
<wildfire>
    <upload-file-info>
        <sha256>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</sha256>
        <md5>d41d8cd98f00b204e9800998ecf8427e</md5>
        <filename>test.pdf</filename>
        <filetype>PDF</filetype>
        <size>12345</size>
        <url></url>
    </upload-file-info>
</wildfire>"""

WILDFIRE_VERDICT_BENIGN_XML = """<?xml version="1.0" encoding="UTF-8"?>
<wildfire>
    <get-verdict-info>
        <sha256>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</sha256>
        <verdict>0</verdict>
        <md5>d41d8cd98f00b204e9800998ecf8427e</md5>
    </get-verdict-info>
</wildfire>"""

WILDFIRE_VERDICT_MALWARE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<wildfire>
    <get-verdict-info>
        <sha256>abc123def456</sha256>
        <verdict>1</verdict>
        <md5>def456</md5>
    </get-verdict-info>
</wildfire>"""

WILDFIRE_VERDICT_PENDING_XML = """<?xml version="1.0" encoding="UTF-8"?>
<wildfire>
    <get-verdict-info>
        <sha256>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</sha256>
        <verdict>-100</verdict>
        <md5>d41d8cd98f00b204e9800998ecf8427e</md5>
    </get-verdict-info>
</wildfire>"""

WILDFIRE_ERROR_XML = """<?xml version="1.0" encoding="UTF-8"?>
<wildfire>
    <error-message>Invalid API key</error-message>
</wildfire>"""


@pytest.fixture
def submit_xml() -> str:
    return WILDFIRE_SUBMIT_XML


@pytest.fixture
def verdict_benign_xml() -> str:
    return WILDFIRE_VERDICT_BENIGN_XML


@pytest.fixture
def verdict_malware_xml() -> str:
    return WILDFIRE_VERDICT_MALWARE_XML


@pytest.fixture
def verdict_pending_xml() -> str:
    return WILDFIRE_VERDICT_PENDING_XML


@pytest.fixture
def error_xml() -> str:
    return WILDFIRE_ERROR_XML


def has_real_airs_key() -> bool:
    """Check if real AIRS credentials are available for integration tests."""
    return bool(os.getenv("PANW_AI_SEC_API_KEY") and os.getenv("PANW_AI_PROFILE"))


def has_real_wildfire_key() -> bool:
    """Check if real WildFire credentials are available for integration tests."""
    return bool(os.getenv("PANW_WILDFIRE_API_KEY"))


skip_no_airs = pytest.mark.skipif(
    not has_real_airs_key(),
    reason="PANW_AI_SEC_API_KEY and PANW_AI_PROFILE not set",
)

skip_no_wildfire = pytest.mark.skipif(
    not has_real_wildfire_key(),
    reason="PANW_WILDFIRE_API_KEY not set",
)

skip_no_both = pytest.mark.skipif(
    not (has_real_airs_key() and has_real_wildfire_key()),
    reason="Both AIRS and WildFire keys required",
)
