"""Configuration and Infrastructure Agent for TLS and service exposure assessment."""

import time
from cybersentinel.agents.base import BaseAgent
from cybersentinel.core.event_bus import EventBus
from cybersentinel.models.assessment import AgentResult, AssessmentContext
from cybersentinel.models.finding import Finding
from cybersentinel.risk.severity import Severity
from cybersentinel.scanners.ports import PortScanner, RealPortScanner, DEFAULT_SAFE_PORTS
from cybersentinel.scanners.tls import TLSScanner, RealTLSScanner
from cybersentinel.utils.ids import generate_finding_id


class ConfigurationAgent(BaseAgent):
    """Audits TLS configuration, expiring certificates, and exposed administrative services."""

    name: str = "Configuration Agent"
    description: str = "Inspects TLS protocol cipher strength, certificates, and port exposure"

    def __init__(
        self,
        tls_scanner: TLSScanner | None = None,
        port_scanner: PortScanner | None = None,
        event_bus: EventBus | None = None,
        pacing: bool = False,
    ):
        super().__init__(event_bus=event_bus, pacing=pacing)
        self.tls_scanner = tls_scanner or RealTLSScanner()
        self.port_scanner = port_scanner or RealPortScanner()

    def run(self, context: AssessmentContext) -> AgentResult:
        start = time.perf_counter()
        findings: list[Finding] = []
        observations: list[str] = []
        errors: list[str] = []
        status = "success"

        primary_asset_id = context.assets[0].id if context.assets else "AST-001"
        admin_asset = context.get_asset("AST-003")
        admin_asset_id = admin_asset.id if admin_asset else primary_asset_id

        # 1. TLS Certificate & Protocol Checks
        self.emit_progress(f"Inspecting TLS configuration for {context.target.host}:443...", step_delay=0.25)
        tls_obs = self.tls_scanner.inspect_tls(context.target.host, port=context.target.port or 443)

        if not tls_obs.tls_enabled and not tls_obs.error:
            observations.append("TLS is not active on target port.")
        elif tls_obs.error and not tls_obs.tls_enabled:
            observations.append(f"TLS inspection note: {tls_obs.error}")
        else:
            observations.append(
                f"TLS active: {tls_obs.tls_version or 'Unknown'} | Cipher: {tls_obs.cipher_suite or 'N/A'}"
            )

            # Check weak protocol version
            if tls_obs.tls_version in {"TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}:
                f = Finding(
                    id=generate_finding_id(len(findings) + 1),
                    title=f"Deprecated TLS Protocol Version Supported ({tls_obs.tls_version})",
                    description=f"Target negotiates obsolete cryptographic protocol {tls_obs.tls_version}.",
                    category="Cryptographic Configuration",
                    severity=Severity.HIGH,
                    severity_score=8,
                    exploitability_score=7,
                    exposure_score=8,
                    asset_criticality_score=8,
                    confidence_score=10,
                    asset_id=primary_asset_id,
                    evidence=[
                        f"Server successfully completed handshake using deprecated protocol {tls_obs.tls_version}.",
                        f"Negotiated cipher suite: {tls_obs.cipher_suite or 'Default'}",
                    ],
                    impact="Obsolete protocols are susceptible to padding oracle attacks (POODLE, BEAST) and lack forward secrecy.",
                    recommendation="Disable TLS 1.0 and TLS 1.1 across all web endpoints; require TLS 1.2 or TLS 1.3.",
                    source_agent=self.name,
                    references=["NIST SP 800-52r2", "RFC 8996"],
                )
                findings.append(f)
                self._emit_finding(f)

            # Check certificate validity and expiration
            if tls_obs.expires_in_days is not None and tls_obs.expires_in_days <= 30:
                is_expired = tls_obs.expires_in_days <= 0
                f = Finding(
                    id=generate_finding_id(len(findings) + 1),
                    title="TLS Certificate Expired" if is_expired else "TLS Certificate Expiring Soon",
                    description=f"The active TLS certificate expires in {tls_obs.expires_in_days} days."
                    if not is_expired
                    else "The active TLS certificate has already expired.",
                    category="Certificate Management",
                    severity=Severity.HIGH if is_expired else Severity.MEDIUM,
                    severity_score=8 if is_expired else 6,
                    exploitability_score=6,
                    exposure_score=9,
                    asset_criticality_score=8,
                    confidence_score=10,
                    asset_id=primary_asset_id,
                    evidence=[
                        f"Certificate subject: {tls_obs.subject}",
                        f"Issuer: {tls_obs.issuer}",
                        f"Remaining validity: {tls_obs.expires_in_days} days",
                    ],
                    impact="Certificate expiration triggers browser security warnings, breaking client trust and access.",
                    recommendation="Renew the certificate and implement automated renewal (e.g. ACME/Certbot).",
                    source_agent=self.name,
                    references=["CA/Browser Forum Baseline Requirements"],
                )
                findings.append(f)
                self._emit_finding(f)

        # 2. Port & Service Exposure Checks (Restricted Safe Port List)
        self.emit_progress(f"Checking restricted safe ports {DEFAULT_SAFE_PORTS}...", step_delay=0.3)
        port_results = self.port_scanner.scan_ports(context.target.host, DEFAULT_SAFE_PORTS)

        open_ports = [p for p in port_results if p.is_open]
        observations.append(f"Discovered {len(open_ports)} open port(s): {[p.port for p in open_ports]}")

        for p in open_ports:
            # Check for exposed administrative services (e.g. 8080)
            if p.port in (8080, 8443) or "admin" in p.service.lower() or (p.banner and "admin" in p.banner.lower()):
                f = Finding(
                    id=generate_finding_id(len(findings) + 1),
                    title=f"Exposed Administrative Service on Port {p.port}",
                    description=f"Administrative management interface is accessible directly from the public network on port {p.port}.",
                    category="Access Control & Exposure",
                    severity=Severity.CRITICAL,
                    severity_score=9,
                    exploitability_score=8,
                    exposure_score=9,
                    asset_criticality_score=10,
                    confidence_score=9,
                    asset_id=admin_asset_id,
                    evidence=[
                        f"Port {p.port} ({p.service}) is open and reachable externally.",
                        f"Service banner: {p.banner or 'Internal Administrative Console'}",
                    ],
                    impact="Public exposure of administrative interfaces drastically increases risk of credential brute force and unauthorized access.",
                    recommendation="Restrict administrative interfaces behind a VPN, zero-trust network access, or firewall whitelist.",
                    source_agent=self.name,
                    references=["CIS Controls v8 - Control 4: Secure Configuration"],
                )
                findings.append(f)
                self._emit_finding(f)

        duration_ms = int((time.perf_counter() - start) * 1000)
        return AgentResult(
            agent_name=self.name,
            status=status,
            duration_ms=duration_ms,
            findings=findings,
            assets=[],
            observations=observations,
            errors=errors,
            metadata={"scanned_ports": DEFAULT_SAFE_PORTS, "open_ports": [p.port for p in open_ports]},
        )

    def _emit_finding(self, finding: Finding) -> None:
        if self.event_bus:
            self.event_bus.emit(
                event_type="finding.discovered",
                agent=self.name,
                message=f"Finding discovered: {finding.title} ({finding.severity.value})",
                metadata={"finding_id": finding.id, "severity": finding.severity.value},
            )
