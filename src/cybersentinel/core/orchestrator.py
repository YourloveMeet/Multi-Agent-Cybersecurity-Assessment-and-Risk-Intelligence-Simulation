"""Central assessment orchestrator coordinating multi-agent pipeline."""

from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING
from cybersentinel.core.event_bus import EventBus
from cybersentinel.models.assessment import AgentResult, AssessmentContext
from cybersentinel.utils.timestamps import utc_now

if TYPE_CHECKING:
    from cybersentinel.agents.base import BaseAgent


class Orchestrator:
    """Coordinates lifecycle, sequential agent execution, and state propagation."""

    def __init__(
        self,
        event_bus: EventBus | None = None,
        agents: list[BaseAgent] | None = None,
    ):
        self.event_bus = event_bus or EventBus()
        self.agents = agents

    def run_assessment(
        self,
        context: AssessmentContext,
        pipeline_agents: list[BaseAgent] | None = None,
    ) -> AssessmentContext:
        """Execute full assessment workflow across the multi-agent team."""
        agents = pipeline_agents or self.agents
        if not agents:
            # Default agent pipeline if none provided
            from cybersentinel.agents.recon import ReconAgent
            from cybersentinel.agents.web_security import WebSecurityAgent
            from cybersentinel.agents.configuration import ConfigurationAgent
            from cybersentinel.agents.risk_intelligence import RiskIntelligenceAgent
            from cybersentinel.agents.report import ReportAgent

            agents = [
                ReconAgent(event_bus=self.event_bus),
                WebSecurityAgent(event_bus=self.event_bus),
                ConfigurationAgent(event_bus=self.event_bus),
                RiskIntelligenceAgent(event_bus=self.event_bus),
                ReportAgent(event_bus=self.event_bus),
            ]

        self.event_bus.emit(
            event_type="assessment.started",
            agent="Orchestrator",
            message=f"Starting multi-agent assessment for {context.target.display_name}",
            metadata={"target": context.target.display_name, "mode": context.mode, "profile": context.profile},
        )

        for agent in agents:
            self.event_bus.emit(
                event_type="agent.started",
                agent=agent.name,
                message=f"Agent activated: {agent.name}",
            )

            start = time.perf_counter()
            try:
                result = agent.run(context)
            except Exception as e:
                duration_ms = int((time.perf_counter() - start) * 1000)
                result = AgentResult(
                    agent_name=agent.name,
                    status="failed",
                    duration_ms=duration_ms,
                    errors=[f"Unhandled agent exception: {str(e)}"],
                    observations=[f"Agent execution encountered critical error: {str(e)}"],
                )
                self.event_bus.emit(
                    event_type="agent.failed",
                    agent=agent.name,
                    message=f"! Agent failed: {str(e)}",
                    metadata={"error": str(e)},
                )

            context.agent_results.append(result)

            # Ingest new assets
            for a in result.assets:
                if not any(existing.id == a.id for existing in context.assets):
                    context.assets.append(a)

            # Ingest new findings if not already the risk or report agent (which manage context.findings directly)
            if agent.name not in ("Risk Intelligence Agent", "Report Agent"):
                context.findings.extend(result.findings)

            # Accumulate observations
            context.observations.extend(result.observations)

            self.event_bus.emit(
                event_type="agent.completed",
                agent=agent.name,
                message=f"Agent {agent.name} finished ({result.status})",
                metadata={"status": result.status, "duration_ms": result.duration_ms},
            )

        context.completed_at = utc_now()

        self.event_bus.emit(
            event_type="assessment.completed",
            agent="Orchestrator",
            message=f"Assessment complete. Risk: {context.overall_risk} ({context.risk_score}/100)",
            metadata={
                "overall_risk": context.overall_risk,
                "risk_score": context.risk_score,
                "finding_count": len(context.findings),
                "duration_seconds": context.duration_seconds,
            },
        )

        return context
