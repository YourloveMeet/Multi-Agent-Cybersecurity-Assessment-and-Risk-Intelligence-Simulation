"""Event models for decoupled event-driven architecture."""

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field
from cybersentinel.utils.timestamps import utc_now


class AssessmentEvent(BaseModel):
    """Event emitted across assessment lifecycle for subscribers (renderers, loggers)."""
    timestamp: datetime = Field(default_factory=utc_now)
    type: str = Field(description="Event type name e.g. agent.started, finding.discovered")
    agent: str | None = Field(default=None, description="Source agent name if applicable")
    message: str = Field(description="Human readable event message")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Structured event payload")
