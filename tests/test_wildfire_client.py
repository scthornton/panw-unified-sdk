"""Tests for the WildFire client and XML parser."""

from pathlib import Path

import pytest

from pan_ai_security.exceptions import WildFireError
from pan_ai_security.verdicts import Category, Verdict
from pan_ai_security.wildfire.xml_parser import parse_submit_response, parse_verdict_response
from tests.conftest import (
    WILDFIRE_ERROR_XML,
    WILDFIRE_SUBMIT_XML,
    WILDFIRE_VERDICT_BENIGN_XML,
    WILDFIRE_VERDICT_MALWARE_XML,
    WILDFIRE_VERDICT_PENDING_XML,
)


class TestXMLParserSubmit:
    """Test WildFire submit response XML parsing."""

    def test_parse_valid_submit(self) -> None:
        result = parse_submit_response(WILDFIRE_SUBMIT_XML)
        assert result.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert result.md5 == "d41d8cd98f00b204e9800998ecf8427e"
        assert result.filename == "test.pdf"
        assert result.file_type == "PDF"
        assert result.size == 12345

    def test_parse_error_response(self) -> None:
        with pytest.raises(WildFireError, match="Invalid API key"):
            parse_submit_response(WILDFIRE_ERROR_XML)

    def test_parse_invalid_xml(self) -> None:
        with pytest.raises(WildFireError, match="Failed to parse"):
            parse_submit_response("not xml at all")

    def test_parse_missing_upload_info(self) -> None:
        xml = "<wildfire><other>data</other></wildfire>"
        with pytest.raises(WildFireError, match="missing upload-file-info"):
            parse_submit_response(xml)


class TestXMLParserVerdict:
    """Test WildFire verdict response XML parsing."""

    def test_parse_benign_verdict(self) -> None:
        result = parse_verdict_response(WILDFIRE_VERDICT_BENIGN_XML)
        assert result.verdict_code == 0
        assert result.is_benign
        assert not result.is_pending
        assert result.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_parse_malware_verdict(self) -> None:
        result = parse_verdict_response(WILDFIRE_VERDICT_MALWARE_XML)
        assert result.verdict_code == 1
        assert result.is_malicious
        assert not result.is_benign

    def test_parse_pending_verdict(self) -> None:
        result = parse_verdict_response(WILDFIRE_VERDICT_PENDING_XML)
        assert result.verdict_code == -100
        assert result.is_pending

    def test_parse_error_verdict(self) -> None:
        with pytest.raises(WildFireError, match="Invalid API key"):
            parse_verdict_response(WILDFIRE_ERROR_XML)

    def test_parse_missing_verdict_element(self) -> None:
        xml = "<wildfire><get-verdict-info><sha256>abc</sha256></get-verdict-info></wildfire>"
        with pytest.raises(WildFireError, match="missing verdict value"):
            parse_verdict_response(xml)

    def test_parse_invalid_verdict_code(self) -> None:
        xml = """<wildfire><get-verdict-info>
            <sha256>abc</sha256><verdict>xyz</verdict>
        </get-verdict-info></wildfire>"""
        with pytest.raises(WildFireError, match="Invalid WildFire verdict code"):
            parse_verdict_response(xml)


class TestWildFireClientHash:
    """Test WildFire client utility methods."""

    def test_hash_bytes(self) -> None:
        from pan_ai_security.wildfire.client import WildFireClient

        result = WildFireClient.hash_file(b"test content")
        assert len(result) == 64  # SHA-256 hex digest
        assert result == "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"

    def test_hash_file_path(self, tmp_path: Path) -> None:
        from pan_ai_security.wildfire.client import WildFireClient

        f = tmp_path / "test.txt"
        f.write_bytes(b"test content")
        result = WildFireClient.hash_file(str(f))
        assert result == "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"
