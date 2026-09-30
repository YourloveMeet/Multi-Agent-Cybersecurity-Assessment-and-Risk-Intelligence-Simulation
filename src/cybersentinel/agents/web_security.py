"""Web Security Agent for inspecting HTTP/HTTPS application security controls."""

import time
from cybersentinel.agents.base import BaseAgent
from cybersentinel.core.event_bus import EventBus
from cybersentinel.models.assessment import AgentResult, AssessmentContext
from cybersentinel.models.finding import Finding
from cybersentinel.risk.severity import Severity
from cybersentinel.scanners.http import HTTPScanner, RealHTTPScanner
from cybersentinel.utils.ids import generate_finding_id


class WebSecurityAgent(BaseAgent):
    """Inspects web headers, cookie controls, transport redirection, and disclosures."""

    name: str = "Web Security Agent"
    description: str = "Evaluates HTTP security headers, cookie flags, and web application controls"

    def __init__(
        self,
        scanner: HTTPScanner | None = None,
        event_bus: EventBus | None = None,
        pacing: bool = False,
    ):
        super().__init__(event_bus=event_bus, pacing=pacing)
        self.scanner = scanner or RealHTTPScanner()

    def run(self, context: AssessmentContext) -> AgentResult:
        start = time.perf_counter()
        findings: list[Finding] = []
        observations: list[str] = []
        errors: list[str] = []
        status = "success"

        self.emit_progress(f"Inspecting HTTP endpoints for {context.target.display_name}...", step_delay=0.25)
        obs = self.scanner.inspect(context.target)

        primary_asset_id = context.assets[0].id if context.assets else "AST-001"

        if not obs.reachable:
            status = "partial"
            msg = obs.error or "HTTP/HTTPS service unreachable or connection timed out"
            errors.append(msg)
            observations.append(f"HTTP inspection incomplete: {msg}")
            self.emit_progress(f"! Web endpoint unreachable: {msg}", step_delay=0.25)
            duration_ms = int((time.perf_counter() - start) * 1000)
            return AgentResult(
                agent_name=self.name,
                status=status,
                duration_ms=duration_ms,
                findings=findings,
                assets=[],
                observations=observations,
                errors=errors,
            )

        observations.append(f"HTTP service responded (status {obs.status_code}) in {obs.response_time_ms}ms")
        self.emit_progress("Auditing Strict-Transport-Security & Content-Security-Policy...", step_delay=0.25)

        # 1. Check HTTP to HTTPS redirection
        if not obs.redirects_to_https and context.target.scheme != "https":
            f = Finding(
                id=generate_finding_id(len(findings) + 1),
                title="Missing HTTP to HTTPS Redirection",
                description="Plain HTTP requests are served without automatic redirection to encrypted HTTPS.",
                category="Transport Security",
                severity=Severity.HIGH,
                severity_score=8,
                exploitability_score=7,
                exposure_score=9,
                asset_criticality_score=8,
                confidence_score=9,
                asset_id=primary_asset_id,
                evidence=["HTTP port responded directly without redirecting to https:// URL scheme."],
                impact="Cleartext transmission allows on-path attackers to eavesdrop or modify traffic.",
                recommendation="Configure web server to enforce immediate 301/308 redirects to HTTPS.",
                source_agent=self.name,
                references=["OWASP Transport Layer Protection Cheat Sheet", "RFC 6797"],
            )
            findings.append(f)
            self._emit_finding(f)

        # 2. Strict-Transport-Security (HSTS)
        if not obs.has_hsts:
            f = Finding(
                id=generate_finding_id(len(findings) + 1),
                title="Missing Strict-Transport-Security (HSTS) Header",
                description="Strict-Transport-Security HTTP header was not observed in HTTPS responses.",
                category="Transport Security",
                severity=Severity.MEDIUM,
                severity_score=5,
                exploitability_score=5,
                exposure_score=8,
                asset_criticality_score=8,
                confidence_score=9,
                asset_id=primary_asset_id,
                evidence=["Strict-Transport-Security header absent from HTTPS response headers."],
                impact="Leaves clients susceptible to SSL stripping and protocol downgrade attacks on first visit.",
                recommendation="Implement Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.",
                source_agent=self.name,
                references=["RFC 6797", "OWASP HSTS Guidelines"],
            )
            findings.append(f)
            self._emit_finding(f)

        # 3. Content-Security-Policy (CSP)
        if not obs.has_csp:
            f = Finding(
                id=generate_finding_id(len(findings) + 1),
                title="Missing Content-Security-Policy (CSP) Header",
                description="Content-Security-Policy header was not provided by the target web application.",
                category="Application Security",
                severity=Severity.HIGH,
                severity_score=7,
                exploitability_score=7,
                exposure_score=8,
                asset_criticality_score=8,
                confidence_score=9,
                asset_id=primary_asset_id,
                evidence=["Content-Security-Policy header was not observed in response."],
                impact="Absence of CSP increases blast radius and exploitation success of Cross-Site Scripting (XSS).",
                recommendation="Deploy a robust Content-Security-Policy restricting script-src, object-src, and frame-ancestors.",
                source_agent=self.name,
                references=["OWASP CSP Cheat Sheet", "W3C CSP Level 3"],
            )
            findings.append(f)
            self._emit_finding(f)

        # 4. X-Content-Type-Options
        if not obs.has_x_content_type_options:
            f = Finding(
                id=generate_finding_id(len(findings) + 1),
                title="Missing X-Content-Type-Options Header",
                description="The X-Content-Type-Options: nosniff header was not present.",
                category="Application Security",
                severity=Severity.MEDIUM,
                severity_score=4,
                exploitability_score=4,
                exposure_score=8,
                asset_criticality_score=7,
                confidence_score=9,
                asset_id=primary_asset_id,
                evidence=["X-Content-Type-Options header was absent."],
                impact="Browsers may attempt MIME-sniffing, potentially executing user-uploaded assets as scripts.",
                recommendation="Set X-Content-Type-Options: nosniff on all HTTP responses.",
                source_agent=self.name,
                references=["MDN X-Content-Type-Options"],
            )
            findings.append(f)
            self._emit_finding(f)

        # 5. X-Frame-Options
        if not obs.has_x_frame_options:
            f = Finding(
                id=generate_finding_id(len(findings) + 1),
                title="Missing X-Frame-Options Clickjacking Protection",
                description="Neither X-Frame-Options nor frame-ancestors CSP was observed.",
                category="Application Security",
                severity=Severity.MEDIUM,
                severity_score=5,
                exploitability_score=5,
                exposure_score=8,
                asset_criticality_score=7,
                confidence_score=9,
                asset_id=primary_asset_id,
                evidence=["X-Frame-Options header not found in server response."],
                impact="Allows malicious third-party frames to overlay the application, enabling clickjacking attacks.",
                recommendation="Set X-Frame-Options: DENY or SAMEORIGIN (or CSP frame-ancestors 'self').",
                source_agent=self.name,
                references=["OWASP Clickjacking Defense Cheat Sheet"],
            )
            findings.append(f)
            self._emit_finding(f)

        # 6. Referrer-Policy
        if not obs.has_referrer_policy:
            f = Finding(
                id=generate_finding_id(len(findings) + 1),
                title="Missing Referrer-Policy Header",
                description="The Referrer-Policy header is omitted, defaulting to potentially permissive browser behavior.",
                category="Information Disclosure",
                severity=Severity.LOW,
                severity_score=2,
                exploitability_score=3,
                exposure_score=7,
                asset_criticality_score=6,
                confidence_score=8,
                asset_id=primary_asset_id,
                evidence=["Referrer-Policy header was absent."],
                impact="Sensitive path parameters or session queries could be leaked to external referrers.",
                recommendation="Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
                source_agent=self.name,
                references=["MDN Referrer-Policy"],
            )
            findings.append(f)
            self._emit_finding(f)

        # 7. Permissions-Policy
        if not obs.has_permissions_policy:
            f = Finding(
                id=generate_finding_id(len(findings) + 1),
                title="Missing Permissions-Policy Header",
                description="No Permissions-Policy header configured to restrict browser API access.",
                category="Hardening",
                severity=Severity.LOW,
                severity_score=2,
                exploitability_score=2,
                exposure_score=6,
                asset_criticality_score=6,
                confidence_score=8,
                asset_id=primary_asset_id,
                evidence=["Permissions-Policy header was absent."],
                impact="Application does not restrict hardware and browser APIs such as geolocation, camera, or microphone.",
                recommendation="Configure Permissions-Policy to explicitly disable unnecessary browser features.",
                source_agent=self.name,
                references=["W3C Permissions Policy"],
            )
            findings.append(f)
            self._emit_finding(f)

        # 8. Server Software & Tech Disclosure
        if obs.server_header or obs.x_powered_by:
            disclosed = []
            if obs.server_header:
                disclosed.append(f"Server: {obs.server_header}")
            if obs.x_powered_by:
                disclosed.append(f"X-Powered-By: {obs.x_powered_by}")

            f = Finding(
                id=generate_finding_id(len(findings) + 1),
                title="Server Technology Banner Disclosure",
                description="Server and backend technology version strings are disclosed in response headers.",
                category="Information Disclosure",
                severity=Severity.LOW,
                severity_score=2,
                exploitability_score=3,
                exposure_score=8,
                asset_criticality_score=7,
                confidence_score=10,
                asset_id=primary_asset_id,
                evidence=disclosed,
                impact="Reveals exact server software versions to attackers, simplifying vulnerability profiling.",
                recommendation="Configure server directives (e.g. ServerTokens Prod, expose_php=Off) to mask banners.",
                source_agent=self.name,
                references=["OWASP Information Disclosure Prevention"],
            )
            findings.append(f)
            self._emit_finding(f)

        # 9. Cookie security inspection
        insecure_cookies = []
        for cookie in obs.cookies:
            missing_flags = []
            if not cookie.httponly:
                missing_flags.append("Missing HttpOnly")
            if not cookie.secure:
                missing_flags.append("Missing Secure")
            if not cookie.samesite:
                missing_flags.append("Missing SameSite")
            if missing_flags:
                insecure_cookies.append(f"Cookie '{cookie.name}': {', '.join(missing_flags)}")

        if insecure_cookies:
            f = Finding(
                id=generate_finding_id(len(findings) + 1),
                title="Insecure Session Cookie Configuration",
                description="Sensitive session or application cookies are transmitted without essential defense flags.",
                category="Session Management",
                severity=Severity.MEDIUM,
                severity_score=6,
                exploitability_score=6,
                exposure_score=8,
                asset_criticality_score=8,
                confidence_score=9,
                asset_id=primary_asset_id,
                evidence=insecure_cookies,
                impact="Cookies without HttpOnly can be stolen via XSS; cookies without SameSite risk CSRF exploitation.",
                recommendation="Enforce Secure, HttpOnly, and SameSite=Lax/Strict flags on all stateful cookies.",
                source_agent=self.name,
                references=["OWASP Session Management Cheat Sheet"],
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
            metadata={"headers_checked": len(obs.headers), "cookies_checked": len(obs.cookies)},
        )

    def _emit_finding(self, finding: Finding) -> None:
        if self.event_bus:
            self.event_bus.emit(
                event_type="finding.discovered",
                agent=self.name,
                message=f"Finding discovered: {finding.title} ({finding.severity.value})",
                metadata={"finding_id": finding.id, "severity": finding.severity.value},
            )
