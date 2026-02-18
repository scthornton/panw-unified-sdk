"""Tests for verdict normalization and merging."""

from pan_ai_security.verdicts import (
    Category,
    ScanVerdict,
    Severity,
    Source,
    ThreatDetail,
    Verdict,
    merge_verdicts,
    verdict_from_wildfire,
)


class TestVerdictFromWildfire:
    """Test WildFire integer code → ScanVerdict mapping."""

    def test_benign(self) -> None:
        v = verdict_from_wildfire(0, sha256="abc123")
        assert v.verdict == Verdict.ALLOW
        assert v.category == Category.BENIGN
        assert v.is_safe
        assert not v.is_blocked
        assert v.threat_count == 0
        assert v.confidence == 1.0

    def test_malware(self) -> None:
        v = verdict_from_wildfire(1, sha256="abc123")
        assert v.verdict == Verdict.BLOCK
        assert v.category == Category.MALICIOUS
        assert v.is_blocked
        assert v.threat_count == 1
        assert v.threats[0].threat_type == "malware"
        assert v.threats[0].severity == Severity.CRITICAL

    def test_grayware(self) -> None:
        v = verdict_from_wildfire(2, sha256="abc123")
        assert v.verdict == Verdict.BLOCK
        assert v.category == Category.GRAYWARE
        assert v.threats[0].threat_type == "grayware"
        assert v.threats[0].severity == Severity.MEDIUM

    def test_phishing(self) -> None:
        v = verdict_from_wildfire(4, sha256="abc123")
        assert v.verdict == Verdict.BLOCK
        assert v.category == Category.PHISHING
        assert v.threats[0].threat_type == "phishing"
        assert v.threats[0].severity == Severity.HIGH

    def test_c2(self) -> None:
        v = verdict_from_wildfire(5, sha256="abc123")
        assert v.verdict == Verdict.BLOCK
        assert v.category == Category.C2
        assert v.threats[0].threat_type == "command_and_control"
        assert v.threats[0].severity == Severity.CRITICAL

    def test_pending(self) -> None:
        v = verdict_from_wildfire(-100, sha256="abc123")
        assert v.verdict == Verdict.PENDING
        assert v.category == Category.PENDING
        assert v.is_pending
        assert v.confidence == 0.0
        assert v.threat_count == 0

    def test_unknown_code_defaults_to_block(self) -> None:
        v = verdict_from_wildfire(999, sha256="abc123")
        assert v.verdict == Verdict.BLOCK
        assert v.category == Category.MALICIOUS

    def test_source_is_wildfire(self) -> None:
        v = verdict_from_wildfire(0, sha256="abc123")
        assert v.source == Source.WILDFIRE

    def test_scan_id_is_sha256(self) -> None:
        v = verdict_from_wildfire(0, sha256="deadbeef")
        assert v.scan_id == "deadbeef"

    def test_duration_ms_preserved(self) -> None:
        v = verdict_from_wildfire(0, sha256="abc", duration_ms=1500)
        assert v.duration_ms == 1500

    def test_raw_response_preserved(self) -> None:
        raw = {"test": "data"}
        v = verdict_from_wildfire(0, sha256="abc", raw_response=raw)
        assert v.raw_response == raw


class TestMergeVerdicts:
    """Test merging AIRS + WildFire verdicts."""

    def _make_verdict(
        self,
        verdict: Verdict = Verdict.ALLOW,
        category: Category = Category.BENIGN,
        source: Source = Source.AIRS,
        threats: list[ThreatDetail] | None = None,
    ) -> ScanVerdict:
        return ScanVerdict(
            verdict=verdict,
            category=category,
            confidence=1.0,
            source=source,
            scan_id="test-id",
            threats=threats or [],
            duration_ms=100,
        )

    def test_both_allow(self) -> None:
        a = self._make_verdict(source=Source.AIRS)
        w = self._make_verdict(source=Source.WILDFIRE)
        merged = merge_verdicts(a, w)
        assert merged.verdict == Verdict.ALLOW
        assert merged.source == Source.COMBINED

    def test_airs_blocks(self) -> None:
        threat = ThreatDetail("injection", Severity.CRITICAL, "test", "prompt")
        a = self._make_verdict(
            verdict=Verdict.BLOCK,
            category=Category.MALICIOUS,
            source=Source.AIRS,
            threats=[threat],
        )
        w = self._make_verdict(source=Source.WILDFIRE)
        merged = merge_verdicts(a, w)
        assert merged.verdict == Verdict.BLOCK
        assert merged.category == Category.MALICIOUS
        assert len(merged.threats) == 1

    def test_wildfire_blocks(self) -> None:
        threat = ThreatDetail("malware", Severity.CRITICAL, "test", "file")
        a = self._make_verdict(source=Source.AIRS)
        w = self._make_verdict(
            verdict=Verdict.BLOCK,
            category=Category.MALICIOUS,
            source=Source.WILDFIRE,
            threats=[threat],
        )
        merged = merge_verdicts(a, w)
        assert merged.verdict == Verdict.BLOCK
        assert len(merged.threats) == 1

    def test_both_block_combines_threats(self) -> None:
        t1 = ThreatDetail("injection", Severity.CRITICAL, "test1", "prompt")
        t2 = ThreatDetail("malware", Severity.CRITICAL, "test2", "file")
        a = self._make_verdict(
            verdict=Verdict.BLOCK, category=Category.MALICIOUS,
            source=Source.AIRS, threats=[t1],
        )
        w = self._make_verdict(
            verdict=Verdict.BLOCK, category=Category.MALICIOUS,
            source=Source.WILDFIRE, threats=[t2],
        )
        merged = merge_verdicts(a, w)
        assert merged.verdict == Verdict.BLOCK
        assert len(merged.threats) == 2

    def test_pending_overrides_allow(self) -> None:
        a = self._make_verdict(source=Source.AIRS)
        w = self._make_verdict(
            verdict=Verdict.PENDING, category=Category.PENDING,
            source=Source.WILDFIRE,
        )
        merged = merge_verdicts(a, w)
        assert merged.verdict == Verdict.PENDING

    def test_duration_is_summed(self) -> None:
        a = self._make_verdict(source=Source.AIRS)
        w = self._make_verdict(source=Source.WILDFIRE)
        a.duration_ms = 100
        w.duration_ms = 200
        merged = merge_verdicts(a, w)
        assert merged.duration_ms == 300

    def test_combined_scan_id(self) -> None:
        a = self._make_verdict(source=Source.AIRS)
        w = self._make_verdict(source=Source.WILDFIRE)
        a.scan_id = "airs-123"
        w.scan_id = "wf-456"
        merged = merge_verdicts(a, w)
        assert merged.scan_id == "airs-123+wf-456"


class TestScanVerdictProperties:
    """Test ScanVerdict dataclass properties."""

    def test_to_dict(self) -> None:
        v = verdict_from_wildfire(1, sha256="abc")
        d = v.to_dict()
        assert d["verdict"] == "block"
        assert d["category"] == "malicious"
        assert d["source"] == "wildfire"
        assert d["is_safe"] is False
        assert len(d["threats"]) == 1

    def test_is_safe_for_benign(self) -> None:
        v = verdict_from_wildfire(0, sha256="abc")
        assert v.is_safe is True
        assert v.is_blocked is False

    def test_is_blocked_for_malware(self) -> None:
        v = verdict_from_wildfire(1, sha256="abc")
        assert v.is_safe is False
        assert v.is_blocked is True
