"""Reconnaissance Agent for safe target discovery and asset enumeration."""

import time
from cybersentinel.agents.base import BaseAgent
from cybersentinel.core.event_bus import EventBus
from cybersentinel.models.asset import Asset
from cybersentinel.models.assessment import AgentResult, AssessmentContext
from cybersentinel.models.finding import Finding
from cybersentinel.scanners.dns import DNSScanner, RealDNSScanner, DemoDNSScanner
from cybersentinel.utils.ids import generate_asset_id


class ReconAgent(BaseAgent):
    """Performs target resolution, reachability verification, and asset mapping."""

    name: str = "Reconnaissance Agent"
    description: str = "Discovers network boundaries, DNS records, and inventory assets"

    def __init__(
        self,
        scanner: DNSScanner | None = None,
        event_bus: EventBus | None = None,
        demo_assets: list[Asset] | None = None,
        pacing: bool = False,
    ):
        super().__init__(event_bus=event_bus, pacing=pacing)
        self.scanner = scanner or RealDNSScanner()
        self.demo_assets = demo_assets

    def run(self, context: AssessmentContext) -> AgentResult:
        start = time.perf_counter()
        observations: list[str] = []
        assets: list[Asset] = []
        findings: list[Finding] = []
        errors: list[str] = []
        status = "success"

        self.emit_progress(f"Resolving target DNS records for {context.target.host}...", step_delay=0.25)
        dns_res = self.scanner.resolve(context.target.host)

        if not dns_res.resolved:
            status = "partial"
            errors.append(dns_res.error or "Target could not be resolved via DNS")
            observations.append(f"DNS resolution failed for {context.target.host}")
            self.emit_progress(f"! Failed to resolve DNS: {dns_res.error}", step_delay=0.25)
        else:
            observations.append(
                f"Resolved {context.target.host} -> {', '.join(dns_res.ip_addresses)} ({dns_res.response_time_ms}ms)"
            )
            context.target.ip = dns_res.ip_addresses[0] if dns_res.ip_addresses else None
            self.emit_progress(f"Target reachable at {', '.join(dns_res.ip_addresses)}", step_delay=0.25)

        # Build asset inventory
        self.emit_progress("Building discovered asset inventory...", step_delay=0.25)
        if self.demo_assets:
            # When demo assets are provided, preserve them
            assets.extend(self.demo_assets)
            for a in assets:
                observations.append(f"Discovered asset: {a.id} ({a.name} on port {a.port or 443})")
                self.emit_progress(f"Discovered asset {a.id} — {a.name}")
        else:
            # Real scan dynamic asset creation
            primary_asset = Asset(
                id=generate_asset_id(1),
                name=f"Public Web Server ({context.target.host})",
                asset_type="web-server",
                host=context.target.host,
                port=context.target.port or (443 if context.target.scheme == "https" else 80),
                exposure="internet",
                environment="production",
                criticality="high",
                criticality_score=8,
                description="Primary host assessed via authorized external perimeter scan",
            )
            assets.append(primary_asset)
            observations.append(f"Registered primary asset {primary_asset.id} for {context.target.host}")
            self.emit_progress(f"Discovered asset {primary_asset.id} — {primary_asset.name}")

        duration_ms = int((time.perf_counter() - start) * 1000)
        return AgentResult(
            agent_name=self.name,
            status=status,
            duration_ms=duration_ms,
            findings=findings,
            assets=assets,
            observations=observations,
            errors=errors,
            metadata={"ip_addresses": dns_res.ip_addresses, "cname": dns_res.canonical_name},
        )
