"""Tests for domain data models."""

import pytest
from pydantic import ValidationError
from datetime import datetime, timezone

from cybersentinel.models import (
    Severity,
    Target,
    Asset,
    Finding,
    AssessmentEvent,
    AgentResult,
    AssessmentContext,
)


def test_target_creation():
    target = Target(host="example.com", port=443, scheme="https", authorized=True)
    assert target.host == "example.com"
    assert target.display_name == "example.com"
    assert target.url == "https://example.com"

    custom_port = Target(host="internal.lab", port=8080, scheme="http")
    assert custom_port.display_name == "internal.lab:8080"
    assert custom_port.url == "http://internal.lab:8080"


def test_asset_creation():
    asset = Asset(
        id="AST-001",
        name="Primary Gateway",
        asset_type="web-server",
        host="api.example.com",
        port=443,
        exposure="internet",
        environment="production",
        criticality="high",
        criticality_score=8,
    )
    assert asset.id == "AST-001"
    assert asset.criticality_score == 8


def test_asset_validation():
    with pytest.raises(ValidationError):
        Asset(id="AST-001", name="Bad Asset", asset_type="srv", criticality_score=15)  # le 10


def test_finding_creation():
    finding = Finding(
        id="FIND-001",
        title="Missing Strict-Transport-Security",
        description="The HTTP response headers do not include HSTS.",
        category="Transport Security",
        severity=Severity.MEDIUM,
        severity_score=5,
        exploitability_score=5,
        exposure_score=8,
        asset_criticality_score=7,
        confidence_score=9,
        source_agent="web_security",
    )
    assert finding.id == "FIND-001"
    assert finding.severity == Severity.MEDIUM
    assert finding.severity_score == 5
    assert finding.risk_score == 0.0
    assert finding.priority == "P3"


def test_assessment_context_helpers():
    target = Target(host="acme-demo.local", mode="simulation")
    context = AssessmentContext(
        assessment_id="ASM-20260930-TEST",
        target=target,
        authorized=True,
        mode="simulation",
        profile="standard",
    )

    asset = Asset(id="AST-001", name="Web", asset_type="web", criticality_score=7)
    context.assets.append(asset)

    f1 = Finding(
        id="FIND-001",
        title="Issue 1",
        description="Desc",
        category="Web",
        severity=Severity.HIGH,
        priority="P1",
        source_agent="agent1",
    )
    f2 = Finding(
        id="FIND-002",
        title="Issue 2",
        description="Desc",
        category="Web",
        severity=Severity.LOW,
        priority="P3",
        source_agent="agent1",
    )
    context.findings.extend([f1, f2])

    assert context.get_asset("AST-001") == asset
    assert context.get_asset("AST-999") is None
    assert context.get_finding("find-001") == f1
    assert context.get_finding("nonexistent") is None

    counts = context.severity_counts
    assert counts["HIGH"] == 1
    assert counts["LOW"] == 1
    assert counts["CRITICAL"] == 0

    p_counts = context.priority_counts
    assert p_counts["P1"] == 1
    assert p_counts["P3"] == 1
    assert p_counts["P0"] == 0


def test_assessment_event():
    event = AssessmentEvent(
        type="agent.completed",
        agent="Recon Agent",
        message="DNS resolution complete",
        metadata={"ips": ["1.1.1.1"]},
    )
    assert event.type == "agent.completed"
    assert event.agent == "Recon Agent"
    assert event.metadata["ips"] == ["1.1.1.1"]
