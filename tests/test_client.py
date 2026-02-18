"""Tests for the UnifiedClient orchestrator."""

from unittest.mock import MagicMock, patch

import pytest

from pan_ai_security.client import UnifiedClient
from pan_ai_security.config import SecurityConfig
from pan_ai_security.exceptions import ConfigurationError
from pan_ai_security.verdicts import Category, ScanVerdict, Source, Verdict


@pytest.fixture
def mock_airs_verdict() -> ScanVerdict:
    return ScanVerdict(
        verdict=Verdict.ALLOW,
        category=Category.BENIGN,
        confidence=1.0,
        source=Source.AIRS,
        scan_id="airs-test-123",
        duration_ms=150,
    )


@pytest.fixture
def mock_wildfire_verdict() -> ScanVerdict:
    return ScanVerdict(
        verdict=Verdict.ALLOW,
        category=Category.BENIGN,
        confidence=1.0,
        source=Source.WILDFIRE,
        scan_id="wf-test-456",
        duration_ms=2500,
    )


class TestUnifiedClientInit:
    """Test client initialization and configuration."""

    def test_no_keys_raises_error(self) -> None:
        with pytest.raises(ConfigurationError, match="No API keys configured"):
            UnifiedClient(config=SecurityConfig(_loaded=True))

    def test_airs_only_mode(self) -> None:
        config = SecurityConfig(
            airs_api_key="key", ai_profile="prof", _loaded=True
        )
        client = UnifiedClient(config=config)
        assert client._airs is not None
        assert client._wildfire is None

    def test_wildfire_only_mode(self) -> None:
        config = SecurityConfig(wildfire_api_key="key", _loaded=True)
        client = UnifiedClient(config=config)
        assert client._airs is None
        assert client._wildfire is not None

    def test_full_mode(self) -> None:
        config = SecurityConfig(
            airs_api_key="key", ai_profile="prof",
            wildfire_api_key="wfkey", _loaded=True
        )
        client = UnifiedClient(config=config)
        assert client._airs is not None
        assert client._wildfire is not None

    def test_airs_key_without_profile_raises(self) -> None:
        with pytest.raises(ConfigurationError, match="PANW_AI_PROFILE is missing"):
            UnifiedClient(config=SecurityConfig(
                airs_api_key="key", _loaded=True
            ))

    def test_kwargs_init(self) -> None:
        """Test initialization with keyword args instead of config."""
        config = SecurityConfig(
            wildfire_api_key="my-wf-key", _loaded=True
        )
        client = UnifiedClient(config=config)
        assert client._wildfire is not None

    def test_repr(self) -> None:
        config = SecurityConfig(wildfire_api_key="key", _loaded=True)
        client = UnifiedClient(config=config)
        assert "file-only" in repr(client)


class TestUnifiedClientTextScan:
    """Test text scanning through the unified client."""

    @patch("pan_ai_security.airs.client.AIRSClient.scan_text")
    def test_scan_text_routes_to_airs(
        self, mock_scan: MagicMock, mock_airs_verdict: ScanVerdict
    ) -> None:
        mock_scan.return_value = mock_airs_verdict
        config = SecurityConfig(
            airs_api_key="key", ai_profile="prof", _loaded=True
        )
        client = UnifiedClient(config=config)
        result = client.scan(prompt="Hello world")
        assert result.source == Source.AIRS
        mock_scan.assert_called_once()

    def test_scan_text_without_airs_raises(self) -> None:
        config = SecurityConfig(wildfire_api_key="key", _loaded=True)
        client = UnifiedClient(config=config)
        with pytest.raises(ConfigurationError, match="Text scanning requires AIRS"):
            client.scan_text(prompt="Hello")


class TestUnifiedClientFileScan:
    """Test file scanning through the unified client."""

    @patch("pan_ai_security.wildfire.client.WildFireClient.scan_file")
    def test_scan_file_routes_to_wildfire(
        self, mock_scan: MagicMock, mock_wildfire_verdict: ScanVerdict
    ) -> None:
        mock_scan.return_value = mock_wildfire_verdict
        config = SecurityConfig(wildfire_api_key="key", _loaded=True)
        client = UnifiedClient(config=config)
        result = client.scan(file=b"fake-pdf-content", filename="test.pdf")
        assert result.source == Source.WILDFIRE
        mock_scan.assert_called_once()

    def test_scan_file_without_wildfire_raises(self) -> None:
        config = SecurityConfig(
            airs_api_key="key", ai_profile="prof", _loaded=True
        )
        client = UnifiedClient(config=config)
        with pytest.raises(ConfigurationError, match="File scanning requires WildFire"):
            client.scan_file(file=b"data")


class TestUnifiedClientContextManager:
    """Test context manager protocol."""

    def test_sync_context_manager(self) -> None:
        config = SecurityConfig(wildfire_api_key="key", _loaded=True)
        with UnifiedClient(config=config) as client:
            assert client._wildfire is not None
