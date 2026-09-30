"""Integration test for full end-to-end demo assessment pipeline."""

import json
from cybersentinel.core.event_bus import EventBus
from cybersentinel.demo.scenario import run_demo_assessment
from cybersentinel.reporting.markdown import MarkdownReportGenerator
from cybersentinel.reporting.json_export import JSONExportGenerator


def test_demo_assessment_completes_end_to_end():
    events_captured = []
    bus = EventBus()
    bus.subscribe(lambda ev: events_captured.append(ev))

    context = run_demo_assessment(event_bus=bus)

    # 1. Pipeline execution status
    assert context.completed_at is not None
    assert context.duration_seconds >= 0.0
    assert len(context.agent_results) == 5

    # 2. Assets & Findings populated
    assert len(context.assets) >= 3
    assert len(context.findings) >= 5

    # 3. Deterministic risk intelligence
    assert context.overall_risk in {"HIGH", "CRITICAL"}
    assert context.risk_score >= 50.0

    # 4. Remediation priorities assigned
    priorities = [f.priority for f in context.findings]
    assert "P0" in priorities or "P1" in priorities

    # 5. Events verified
    event_types = [ev.type for ev in events_captured]
    assert "assessment.started" in event_types
    assert "agent.started" in event_types
    assert "agent.completed" in event_types
    assert "risk.calculated" in event_types
    assert "assessment.completed" in event_types

    # 6. Report generation validation
    md_report = MarkdownReportGenerator().generate(context)
    assert "# CyberSentinel Security Assessment Report" in md_report
    assert "Executive Summary" in md_report
    assert "Discovered Asset Inventory" in md_report
    assert "Prioritized Remediation Queue" in md_report

    # 7. JSON export validation
    json_str = JSONExportGenerator().generate(context)
    data = json.loads(json_str)
    assert data["assessment"]["target"] == "acme-demo.local"
    assert data["assessment"]["overall_risk"] == context.overall_risk
    assert len(data["findings"]) == len(context.findings)
    assert len(data["assets"]) == len(context.assets)
