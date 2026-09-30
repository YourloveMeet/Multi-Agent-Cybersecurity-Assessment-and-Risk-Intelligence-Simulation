"""Assessment and Agent execution data models."""

from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field

from cybersentinel.models.asset import Asset
from cybersentinel.models.finding import Finding
from cybersentinel.models.target import Target
from cybersentinel.risk.severity import Severity
from cybersentinel.utils.timestamps import utc_now


class AgentResult(BaseModel):
    """Execution output from a single agent."""
    agent_name: str
    status: Literal["success", "partial", "failed"]
    duration_ms: int = 0
    findings: list[Finding] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssessmentContext(BaseModel):
    """Central state maintained throughout an assessment session."""
    assessment_id: str
    target: Target
    authorized: bool = False
    mode: str = "authorized"
    profile: str = "standard"

    assets: list[Asset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    observations: list[str] = Field(default_factory=list)
    agent_results: list[AgentResult] = Field(default_factory=list)

    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None

    overall_risk: str = "LOW"
    risk_score: float = 0.0

    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        """Calculate total assessment execution duration in seconds."""
        if not self.completed_at:
            return 0.0
        return max(0.0, (self.completed_at - self.started_at).total_seconds())

    @property
    def severity_counts(self) -> dict[str, int]:
        """Return counts of findings grouped by severity."""
        counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    @property
    def priority_counts(self) -> dict[str, int]:
        """Return counts of findings grouped by priority."""
        counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
        for finding in self.findings:
            counts[finding.priority] = counts.get(finding.priority, 0) + 1
        return counts

    def get_asset(self, asset_id: str) -> Asset | None:
        """Find asset by ID."""
        for a in self.assets:
            if a.id == asset_id:
                return a
        return None

    def get_finding(self, finding_id: str) -> Finding | None:
        """Find finding by ID (case-insensitive)."""
        target_id = finding_id.strip().upper()
        for f in self.findings:
            if f.id.upper() == target_id:
                return f
        return None
