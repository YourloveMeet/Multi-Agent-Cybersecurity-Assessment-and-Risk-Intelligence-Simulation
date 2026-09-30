"""Unit tests for finding aggregation and deduplication."""

import pytest
from cybersentinel.models import Finding, Severity
from cybersentinel.core.aggregator import aggregate_findings


def test_aggregate_empty_findings():
    assert aggregate_findings([]) == []


def test_aggregate_distinct_findings():
    f1 = Finding(
        id="RAW-1",
        title="Missing CSP",
        description="Desc",
        category="Headers",
        severity=Severity.HIGH,
        source_agent="web_agent",
    )
    f2 = Finding(
        id="RAW-2",
        title="Exposed SSH",
        description="Desc",
        category="Network",
        severity=Severity.CRITICAL,
        source_agent="config_agent",
    )

    result = aggregate_findings([f1, f2])
    assert len(result) == 2
    assert result[0].id == "FIND-001"
    assert result[1].id == "FIND-002"


def test_duplicate_findings_are_merged():
    # Both agents observe Missing HSTS on the same asset AST-001
    f1 = Finding(
        id="RAW-A",
        title="Missing HSTS",
        description="HTTP header missing",
        category="Transport Security",
        severity=Severity.LOW,
        severity_score=2,
        asset_id="AST-001",
        evidence=["Response headers did not include Strict-Transport-Security"],
        source_agent="web_agent",
    )
    f2 = Finding(
        id="RAW-B",
        title="missing hsts",  # lower case title variation
        description="Transport hardening missing",
        category="Transport Security",
        severity=Severity.MEDIUM,
        severity_score=5,
        asset_id="AST-001",
        evidence=["Port 443 response lacking HSTS policy"],
        source_agent="config_agent",
    )

    merged = aggregate_findings([f1, f2])
    assert len(merged) == 1
    item = merged[0]
    assert item.id == "FIND-001"
    assert item.severity == Severity.MEDIUM
    assert item.severity_score == 5
    assert len(item.evidence) == 2
    assert "web_agent" in item.source_agent
    assert "config_agent" in item.source_agent
