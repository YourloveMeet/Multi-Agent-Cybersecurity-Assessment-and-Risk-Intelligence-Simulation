from cybersentinel.core.event_bus import EventBus
from cybersentinel.core.orchestrator import Orchestrator
from cybersentinel.models.assessment import AssessmentContext
from cybersentinel.models.target import Target
from cybersentinel.scanners.dns import RealDNSScanner
from cybersentinel.scanners.http import RealHTTPScanner
from cybersentinel.scanners.ports import RealPortScanner
from cybersentinel.scanners.tls import RealTLSScanner
from cybersentinel.utils.ids import generate_assessment_id
from cybersentinel.utils.validation import normalize_target, validate_target_host


def create_real_assessment_pipeline(
    target_input: str,
    profile: str = "standard",
    authorized: bool = False,
    event_bus: EventBus | None = None,
    pacing: bool = False,
) -> tuple[AssessmentContext, Orchestrator, list]:
    """Assemble live scanning pipeline for an authorized target."""
    from cybersentinel.agents.configuration import ConfigurationAgent
    from cybersentinel.agents.recon import ReconAgent
    from cybersentinel.agents.report import ReportAgent
    from cybersentinel.agents.risk_intelligence import RiskIntelligenceAgent
    from cybersentinel.agents.web_security import WebSecurityAgent

    bus = event_bus or EventBus()
    host, port = normalize_target(target_input)

    if not validate_target_host(host):
        raise ValueError(f"Invalid host or IP address: '{target_input}'")

    target = Target(
        host=host,
        port=port or 443,
        scheme="https",
        mode="authorized",
        profile="quick" if profile == "quick" else "standard",
        authorized=authorized,
    )

    context = AssessmentContext(
        assessment_id=generate_assessment_id("ASM-LIVE"),
        target=target,
        authorized=authorized,
        mode="authorized",
        profile=target.profile,
    )

    # Real safe scanner implementations
    dns_scanner = RealDNSScanner()
    http_scanner = RealHTTPScanner()
    tls_scanner = RealTLSScanner()
    port_scanner = RealPortScanner()

    recon_agent = ReconAgent(scanner=dns_scanner, event_bus=bus, pacing=pacing)
    web_agent = WebSecurityAgent(scanner=http_scanner, event_bus=bus, pacing=pacing)

    agents = [recon_agent, web_agent]

    if profile != "quick":
        config_agent = ConfigurationAgent(
            tls_scanner=tls_scanner,
            port_scanner=port_scanner,
            event_bus=bus,
            pacing=pacing,
        )
        agents.append(config_agent)

    risk_agent = RiskIntelligenceAgent(event_bus=bus, pacing=pacing)
    report_agent = ReportAgent(event_bus=bus, pacing=pacing)
    agents.extend([risk_agent, report_agent])

    orchestrator = Orchestrator(event_bus=bus, agents=agents)
    return context, orchestrator, agents
