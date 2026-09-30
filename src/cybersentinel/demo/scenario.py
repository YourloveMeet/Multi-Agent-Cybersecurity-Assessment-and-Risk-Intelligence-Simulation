"""Deterministic demo scenario builder and runner."""

from cybersentinel.agents.configuration import ConfigurationAgent
from cybersentinel.agents.recon import ReconAgent
from cybersentinel.agents.report import ReportAgent
from cybersentinel.agents.risk_intelligence import RiskIntelligenceAgent
from cybersentinel.agents.web_security import WebSecurityAgent
from cybersentinel.core.event_bus import EventBus
from cybersentinel.core.orchestrator import Orchestrator
from cybersentinel.demo.data import load_demo_target_data
from cybersentinel.models.asset import Asset
from cybersentinel.models.assessment import AssessmentContext
from cybersentinel.models.target import Target
from cybersentinel.scanners.dns import DemoDNSScanner
from cybersentinel.scanners.http import DemoHTTPScanner
from cybersentinel.scanners.ports import DemoPortScanner
from cybersentinel.scanners.tls import DemoTLSScanner
from cybersentinel.utils.ids import generate_assessment_id


def build_demo_pipeline(
    event_bus: EventBus | None = None,
    pacing: bool = False,
) -> tuple[AssessmentContext, Orchestrator, list]:
    """Assemble deterministic demo assessment context, agents, and orchestrator."""
    bus = event_bus or EventBus()
    data = load_demo_target_data()

    target_info = data.get("target", {})
    target = Target(
        host=target_info.get("host", "acme-demo.local"),
        port=443,
        scheme="https",
        mode="simulation",
        profile="standard",
        authorized=True,
    )

    context = AssessmentContext(
        assessment_id=generate_assessment_id("ASM-DEMO"),
        target=target,
        authorized=True,
        mode="simulation",
        profile="standard",
    )

    demo_assets = [Asset(**a) for a in data.get("assets", [])]

    # Instantiate specialized agents wired with deterministic demo scanners
    recon_agent = ReconAgent(
        scanner=DemoDNSScanner(data),
        event_bus=bus,
        demo_assets=demo_assets,
        pacing=pacing,
    )
    web_agent = WebSecurityAgent(
        scanner=DemoHTTPScanner(data),
        event_bus=bus,
        pacing=pacing,
    )
    config_agent = ConfigurationAgent(
        tls_scanner=DemoTLSScanner(data),
        port_scanner=DemoPortScanner(data),
        event_bus=bus,
        pacing=pacing,
    )
    risk_agent = RiskIntelligenceAgent(event_bus=bus, pacing=pacing)
    report_agent = ReportAgent(event_bus=bus, pacing=pacing)

    agents = [recon_agent, web_agent, config_agent, risk_agent, report_agent]
    orchestrator = Orchestrator(event_bus=bus, agents=agents)

    return context, orchestrator, agents


def run_demo_assessment(
    event_bus: EventBus | None = None,
    pacing: bool = False,
) -> AssessmentContext:
    """Execute complete deterministic demo assessment."""
    context, orchestrator, agents = build_demo_pipeline(event_bus=event_bus, pacing=pacing)
    return orchestrator.run_assessment(context, pipeline_agents=agents)
