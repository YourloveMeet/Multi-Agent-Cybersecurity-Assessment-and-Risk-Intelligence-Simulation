"""Finding data model representing normalized security vulnerabilities and issues."""

from typing import Any
from pydantic import BaseModel, Field
from cybersentinel.risk.severity import Severity


class Finding(BaseModel):
    """Normalized security finding produced by an agent."""
    id: str = Field(description="Unique finding identifier, e.g. FIND-001")
    title: str = Field(description="Concise description of the vulnerability/misconfiguration")
    description: str = Field(description="Detailed finding explanation")
    category: str = Field(description="Finding category: e.g. Transport Security, Access Control, Headers")
    severity: Severity = Field(default=Severity.MEDIUM, description="Finding technical severity")

    asset_id: str | None = Field(default=None, description="Associated asset identifier (AST-xxx)")

    evidence: list[str] = Field(default_factory=list, description="Observed evidence or proofs of weakness")
    impact: str = Field(default="", description="Technical and business impact summary")
    recommendation: str = Field(default="", description="Actionable remediation guidance")

    severity_score: int = Field(default=5, ge=1, le=10, description="Base technical severity (1-10)")
    exploitability_score: int = Field(default=5, ge=1, le=10, description="Ease of exploitation (1-10)")
    exposure_score: int = Field(default=5, ge=1, le=10, description="Exposure surface rating (1-10)")
    asset_criticality_score: int = Field(default=5, ge=1, le=10, description="Associated asset criticality (1-10)")
    confidence_score: int = Field(default=8, ge=1, le=10, description="Detection confidence rating (1-10)")

    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Normalized risk score (0-100)")
    priority: str = Field(default="P3", description="Remediation priority: P0, P1, P2, P3")

    source_agent: str = Field(description="Agent that originated the finding")
    references: list[str] = Field(default_factory=list, description="External security references (OWASP, CIS, RFC)")

    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary scanner metadata")
