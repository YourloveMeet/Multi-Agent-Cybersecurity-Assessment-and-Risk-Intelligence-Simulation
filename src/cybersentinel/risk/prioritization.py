"""Remediation prioritization engine and queue ordering."""

from typing import Literal
from cybersentinel.models.finding import Finding
from cybersentinel.risk.severity import Severity

PriorityLevel = Literal["P0", "P1", "P2", "P3"]

PRIORITY_DESCRIPTIONS = {
    "P0": "Immediate Attention (Active Exposure / Critical Impact)",
    "P1": "High Priority (Remediate within standard SLA / High Risk)",
    "P2": "Planned Remediation (Remediate in next release sprint)",
    "P3": "Low Priority / Hardening (Best-practice hardening)",
}

PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def determine_priority(finding: Finding) -> PriorityLevel:
    """Assign deterministic priority level based on risk score and severity."""
    # Critical risk (>= 75) or Critical technical severity -> P0 or P1
    if finding.risk_score >= 80.0 or (finding.severity == Severity.CRITICAL and finding.risk_score >= 70.0):
        return "P0"
    elif finding.risk_score >= 65.0 or finding.severity in (Severity.CRITICAL, Severity.HIGH):
        return "P1"
    elif finding.risk_score >= 40.0 or finding.severity == Severity.MEDIUM:
        return "P2"
    else:
        return "P3"


def sort_findings_by_priority(findings: list[Finding]) -> list[Finding]:
    """Sort findings into an actionable remediation queue.
    
    Ordered by:
      1. Priority Level (P0 -> P1 -> P2 -> P3)
      2. Risk Score (Descending)
      3. Base Severity Score (Descending)
    """
    return sorted(
        findings,
        key=lambda f: (
            PRIORITY_ORDER.get(f.priority, 99),
            -f.risk_score,
            -f.severity_score,
            f.id,
        ),
    )
