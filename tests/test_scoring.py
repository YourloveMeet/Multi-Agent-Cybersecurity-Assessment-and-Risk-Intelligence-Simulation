"""Unit tests for deterministic risk scoring and prioritization."""

import pytest
from cybersentinel.models import Asset, Finding, Severity
from cybersentinel.risk.scoring import (
    calculate_finding_risk,
    calculate_overall_risk,
    get_risk_category,
)
from cybersentinel.risk.prioritization import (
    determine_priority,
    sort_findings_by_priority,
)


def test_risk_score_is_bounded():
    """Verify that scores are strictly bounded between 0 and 100 under all conditions."""
    for s in [1, 5, 10]:
        for e in [1, 5, 10]:
            for x in [1, 5, 10]:
                for a in [1, 5, 10]:
                    finding = Finding(
                        id="FIND-TEST",
                        title="Test",
                        description="Test",
                        category="Test",
                        severity=Severity.HIGH,
                        severity_score=s,
                        exploitability_score=e,
                        exposure_score=x,
                        asset_criticality_score=a,
                        confidence_score=10,
                        source_agent="test",
                    )
                    score, category = calculate_finding_risk(finding)
                    assert 0.0 <= score <= 100.0
                    assert category in {"LOW", "MODERATE", "HIGH", "CRITICAL"}


def test_risk_categories():
    assert get_risk_category(0.0) == "LOW"
    assert get_risk_category(24.9) == "LOW"
    assert get_risk_category(25.0) == "MODERATE"
    assert get_risk_category(49.9) == "MODERATE"
    assert get_risk_category(50.0) == "HIGH"
    assert get_risk_category(74.9) == "HIGH"
    assert get_risk_category(75.0) == "CRITICAL"
    assert get_risk_category(100.0) == "CRITICAL"


def test_asset_criticality_influences_risk():
    """Higher asset criticality should yield a higher risk score for identical technical issues."""
    low_asset = Asset(id="AST-001", name="Dev box", asset_type="dev", criticality_score=2)
    high_asset = Asset(id="AST-002", name="Prod Gateway", asset_type="web", criticality_score=10)

    finding = Finding(
        id="FIND-HSTS",
        title="Missing HSTS",
        description="No HSTS",
        category="Transport",
        severity=Severity.MEDIUM,
        severity_score=5,
        exploitability_score=5,
        exposure_score=8,
        asset_criticality_score=5,
        source_agent="web",
    )

    score_low, _ = calculate_finding_risk(finding, asset=low_asset)
    score_high, _ = calculate_finding_risk(finding, asset=high_asset)

    assert score_high > score_low


def test_prioritization_levels():
    f_crit = Finding(
        id="FIND-001",
        title="Exposed Admin Console",
        description="Desc",
        category="Access",
        severity=Severity.CRITICAL,
        risk_score=92.0,
        source_agent="config",
    )
    f_high = Finding(
        id="FIND-002",
        title="Weak TLS",
        description="Desc",
        category="Crypto",
        severity=Severity.HIGH,
        risk_score=72.0,
        source_agent="config",
    )
    f_med = Finding(
        id="FIND-003",
        title="Missing CSP",
        description="Desc",
        category="Headers",
        severity=Severity.MEDIUM,
        risk_score=48.0,
        source_agent="web",
    )
    f_low = Finding(
        id="FIND-004",
        title="Server Banner",
        description="Desc",
        category="Info",
        severity=Severity.LOW,
        risk_score=20.0,
        source_agent="web",
    )

    assert determine_priority(f_crit) == "P0"
    assert determine_priority(f_high) == "P1"
    assert determine_priority(f_med) == "P2"
    assert determine_priority(f_low) == "P3"


def test_overall_risk_calculation():
    assert calculate_overall_risk([]) == (0.0, "LOW")

    f1 = Finding(
        id="FIND-1",
        title="Issue 1",
        description="D",
        category="C",
        severity=Severity.CRITICAL,
        risk_score=85.0,
        source_agent="a",
    )
    score, cat = calculate_overall_risk([f1])
    assert score == 85.0
    assert cat == "CRITICAL"


def test_sort_findings_by_priority():
    f1 = Finding(id="F1", title="1", description="", category="", priority="P3", risk_score=20.0, source_agent="")
    f2 = Finding(id="F2", title="2", description="", category="", priority="P0", risk_score=90.0, source_agent="")
    f3 = Finding(id="F3", title="3", description="", category="", priority="P1", risk_score=70.0, source_agent="")
    f4 = Finding(id="F4", title="4", description="", category="", priority="P1", risk_score=75.0, source_agent="")

    ordered = sort_findings_by_priority([f1, f2, f3, f4])
    assert [f.id for f in ordered] == ["F2", "F4", "F3", "F1"]
