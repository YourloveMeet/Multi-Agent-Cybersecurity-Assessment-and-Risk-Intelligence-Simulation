"""Unit tests for individual specialized agents."""

import pytest
from cybersentinel.agents import (
    ReconAgent,
    WebSecurityAgent,
    ConfigurationAgent,
    RiskIntelligenceAgent,
    ReportAgent,
)
from cybersentinel.core.event_bus import EventBus
from cybersentinel.demo.data import load_demo_target_data
from cybersentinel.models import AssessmentContext, Target, Asset
from cybersentinel.scanners import (
    DemoDNSScanner,
    DemoHTTPScanner,
    DemoTLSScanner,
    DemoPortScanner,
)


@pytest.fixture
def demo_data():
    return load_demo_target_data()


@pytest.fixture
def context(demo_data):
    target = Target(host="acme-demo.local", mode="simulation", authorized=True)
    return AssessmentContext(
        assessment_id="ASM-TEST-001",
        target=target,
        authorized=True,
        mode="simulation",
        profile="standard",
    )


def test_recon_agent(demo_data, context):
    bus = EventBus()
    demo_assets = [Asset(**a) for a in demo_data.get("assets", [])]
    agent = ReconAgent(scanner=DemoDNSScanner(demo_data), event_bus=bus, demo_assets=demo_assets)

    result = agent.run(context)
    assert result.status == "success"
    assert len(result.assets) == len(demo_assets)
    assert context.target.ip is not None


def test_web_security_agent(demo_data, context):
    bus = EventBus()
    agent = WebSecurityAgent(scanner=DemoHTTPScanner(demo_data), event_bus=bus)

    result = agent.run(context)
    assert result.status == "success"
    assert len(result.findings) > 0

    titles = [f.title for f in result.findings]
    assert any("HSTS" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)


def test_configuration_agent(demo_data, context):
    bus = EventBus()
    agent = ConfigurationAgent(
        tls_scanner=DemoTLSScanner(demo_data),
        port_scanner=DemoPortScanner(demo_data),
        event_bus=bus,
    )

    result = agent.run(context)
    assert result.status == "success"
    assert len(result.findings) > 0

    titles = [f.title for f in result.findings]
    # Check that exposed administrative service is discovered
    assert any("Administrative Service" in t or "Port 8080" in t for t in titles)


def test_risk_intelligence_agent(demo_data, context):
    bus = EventBus()
    demo_assets = [Asset(**a) for a in demo_data.get("assets", [])]
    context.assets.extend(demo_assets)

    # Populate some findings
    web_agent = WebSecurityAgent(scanner=DemoHTTPScanner(demo_data), event_bus=bus)
    web_res = web_agent.run(context)
    context.findings.extend(web_res.findings)

    risk_agent = RiskIntelligenceAgent(event_bus=bus)
    result = risk_agent.run(context)

    assert result.status == "success"
    assert context.risk_score > 0.0
    assert context.overall_risk in {"LOW", "MODERATE", "HIGH", "CRITICAL"}
    # Verify prioritization is populated
    assert all(f.priority in {"P0", "P1", "P2", "P3"} for f in context.findings)
