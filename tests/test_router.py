"""Tests for the smart content router."""

import tempfile
from pathlib import Path

import pytest

from pan_ai_security.exceptions import ContentRouterError
from pan_ai_security.router import RouteTarget, route


class TestRouteDecision:
    """Test content routing logic."""

    def test_text_prompt_routes_to_airs(self) -> None:
        decision = route(prompt="Hello, how are you?")
        assert decision.target == RouteTarget.AIRS
        assert decision.prompt == "Hello, how are you?"
        assert decision.has_text
        assert not decision.has_file

    def test_text_response_routes_to_airs(self) -> None:
        decision = route(response="I'm doing well, thanks!")
        assert decision.target == RouteTarget.AIRS
        assert decision.response == "I'm doing well, thanks!"

    def test_file_path_routes_to_wildfire(self) -> None:
        decision = route(file="/tmp/test.pdf")
        assert decision.target == RouteTarget.WILDFIRE
        assert decision.file == "/tmp/test.pdf"
        assert decision.has_file
        assert not decision.has_text

    def test_file_bytes_routes_to_wildfire(self) -> None:
        decision = route(file=b"%PDF-1.4 test content", filename="test.pdf")
        assert decision.target == RouteTarget.WILDFIRE
        assert decision.file == b"%PDF-1.4 test content"
        assert decision.filename == "test.pdf"

    def test_path_object_routes_to_wildfire(self) -> None:
        decision = route(file=Path("/tmp/test.exe"))
        assert decision.target == RouteTarget.WILDFIRE

    def test_mixed_content_routes_to_both(self) -> None:
        decision = route(prompt="Analyze this", file="/tmp/doc.pdf")
        assert decision.target == RouteTarget.BOTH
        assert decision.has_text
        assert decision.has_file

    def test_no_content_raises_error(self) -> None:
        with pytest.raises(ContentRouterError, match="Nothing to scan"):
            route()

    def test_none_values_raise_error(self) -> None:
        with pytest.raises(ContentRouterError, match="Nothing to scan"):
            route(prompt=None, file=None)

    def test_empty_string_raises_error(self) -> None:
        with pytest.raises(ContentRouterError, match="Nothing to scan"):
            route(prompt="", response="")

    def test_file_path_autodetect_from_prompt(self) -> None:
        """If prompt is an existing file path, auto-route to WildFire."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(b"%PDF-1.4 test")
            f.flush()
            decision = route(prompt=f.name)
            assert decision.target == RouteTarget.WILDFIRE
            assert decision.file == f.name

    def test_prompt_with_response(self) -> None:
        decision = route(prompt="Hello", response="World")
        assert decision.target == RouteTarget.AIRS
        assert decision.prompt == "Hello"
        assert decision.response == "World"
