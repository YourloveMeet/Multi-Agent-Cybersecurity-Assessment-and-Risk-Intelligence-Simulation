"""Risk Intelligence Agent for contextual risk scoring and remediation prioritization."""

import time
from cybersentinel.agents.base import BaseAgent
from cybersentinel.core.aggregator import aggregate_findings
from cybersentinel.core.event_bus import EventBus
from cybersentinel.models.assessment import AgentResult, AssessmentContext
from cybersentinel.models.finding import Finding
from cybersentinel.risk.prioritization import determine_priority, sort_findings_by_priority
from cybersentinel.risk.scoring import calculate_finding_risk, calculate_overall_risk


class RiskIntelligenceAgent(BaseAgent):
    """Correlates findings with business assets, calculates risk scores, and generates prioritized remediation."""

    name: str = "Risk Intelligence Agent"
    description: str = "Performs finding correlation, contextual business risk scoring, and prioritizes remediation"

    def __init__(self, event_bus: EventBus | None = None, pacing: bool = False):
        super().__init__(event_bus=event_bus, pacing=pacing)

    def run(self, context: AssessmentContext) -> AgentResult:
        start = time.perf_counter()
        observations: list[str] = []

        self.emit_progress("Deduplicating and correlating agent findings...", step_delay=0.25)
        aggregated = aggregate_findings(context.findings)
        observations.append(f"Aggregated {len(context.findings)} raw observations into {len(aggregated)} unique findings")

        self.emit_progress("Correlating vulnerabilities with asset criticality...", step_delay=0.3)
        processed_findings: list[Finding] = []

        for f in aggregated:
            # Correlate with asset
            asset = context.get_asset(f.asset_id) if f.asset_id else None
            if asset:
                f.asset_criticality_score = asset.criticality_score

            score, _ = calculate_finding_risk(f, asset=asset)
            f.risk_score = score
            f.priority = determine_priority(f)
            processed_findings.append(f)

        # Sort into remediation queue
        remediation_queue = sort_findings_by_priority(processed_findings)
        context.findings = remediation_queue

        # Calculate overall assessment risk
        overall_score, overall_category = calculate_overall_risk(remediation_queue)
        context.risk_score = overall_score
        context.overall_risk = overall_category

        observations.append(f"Assessment Overall Risk: {overall_category} ({overall_score}/100)")
        self.emit_progress(f"Overall risk calculated: {overall_category} ({overall_score}/100)")

        if self.event_bus:
            self.event_bus.emit(
                event_type="risk.calculated",
                agent=self.name,
                message=f"Overall risk: {overall_category} ({overall_score}/100)",
                metadata={"risk_score": overall_score, "overall_risk": overall_category},
            )

        duration_ms = int((time.perf_counter() - start) * 1000)
        return AgentResult(
            agent_name=self.name,
            status="success",
            duration_ms=duration_ms,
            findings=remediation_queue,
            assets=[],
            observations=observations,
            metadata={
                "overall_risk": overall_category,
                "risk_score": overall_score,
                "finding_count": len(remediation_queue),
            },
        )
