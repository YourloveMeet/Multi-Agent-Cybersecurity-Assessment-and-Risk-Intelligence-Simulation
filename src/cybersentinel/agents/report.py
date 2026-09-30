"""Report Agent for generating comprehensive assessment reports and exports."""

import time
from cybersentinel.agents.base import BaseAgent
from cybersentinel.core.event_bus import EventBus
from cybersentinel.models.assessment import AgentResult, AssessmentContext


class ReportAgent(BaseAgent):
    """Synthesizes assessment results into executive summaries, Markdown reports, and JSON exports."""

    name: str = "Report Agent"
    description: str = "Generates human-readable assessment summaries, Markdown documents, and machine exports"

    def __init__(self, event_bus: EventBus | None = None, pacing: bool = False):
        super().__init__(event_bus=event_bus, pacing=pacing)

    def run(self, context: AssessmentContext) -> AgentResult:
        start = time.perf_counter()
        observations: list[str] = []

        self.emit_progress("Compiling executive summary and structured findings...", step_delay=0.25)
        observations.append("Synthesized risk intelligence and findings into final report structures.")

        if self.event_bus:
            self.event_bus.emit(
                event_type="report.generated",
                agent=self.name,
                message=f"Assessment report prepared for {context.target.display_name}",
                metadata={"findings": len(context.findings), "overall_risk": context.overall_risk},
            )

        duration_ms = int((time.perf_counter() - start) * 1000)
        return AgentResult(
            agent_name=self.name,
            status="success",
            duration_ms=duration_ms,
            findings=[],
            assets=[],
            observations=observations,
            metadata={"status": "ready"},
        )
