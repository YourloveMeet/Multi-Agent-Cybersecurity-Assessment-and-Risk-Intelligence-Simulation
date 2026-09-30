"""Base Agent definition following the unified agent interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
import time
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from cybersentinel.core.event_bus import EventBus

from cybersentinel.models.assessment import AgentResult, AssessmentContext


class BaseAgent(ABC):
    """Abstract base class for all specialized assessment agents."""

    name: str = "Base Agent"
    description: str = "Base assessment agent"

    def __init__(self, event_bus: EventBus | None = None, pacing: bool = False):
        self.event_bus = event_bus
        self.pacing = pacing

    def emit_progress(
        self,
        message: str,
        metadata: dict[str, Any] | None = None,
        step_delay: float = 0.25,
    ) -> None:
        """Helper to emit agent progress events to the event bus with optional pacing delay."""
        if self.event_bus:
            self.event_bus.emit(
                event_type="agent.progress",
                agent=self.name,
                message=message,
                metadata=metadata or {},
            )
        if self.pacing and step_delay > 0:
            time.sleep(step_delay)

    @abstractmethod
    def run(self, context: AssessmentContext) -> AgentResult:
        """Execute agent inspection logic against assessment context."""
        ...
