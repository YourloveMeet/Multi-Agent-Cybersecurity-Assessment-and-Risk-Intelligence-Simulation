"""Knowledge base rules and intelligence provider for finding explanations and rationales."""

from typing import Protocol
from cybersentinel.models.finding import Finding
from cybersentinel.risk.prioritization import PRIORITY_DESCRIPTIONS


class IntelligenceProvider(Protocol):
    """Protocol for finding explanation and risk intelligence providers."""
    def explain_finding(self, finding: Finding) -> str:
        ...

    def recommend_finding(self, finding: Finding) -> str:
        ...


class RuleBasedIntelligenceProvider:
    """Deterministic, built-in intelligence provider requiring no external API keys."""

    def explain_finding(self, finding: Finding) -> str:
        """Generate structured terminal explanation for a finding."""
        lines = [
            f"[bold]{finding.id} — {finding.title}[/bold]",
            f"Category: {finding.category} | Severity: {finding.severity.value} | Priority: {finding.priority}",
            "",
            "[bold underline]WHY IT MATTERS[/bold underline]",
            finding.impact or finding.description,
            "",
            "[bold underline]OBSERVED EVIDENCE[/bold underline]",
        ]

        if finding.evidence:
            for ev in finding.evidence:
                lines.append(f"  • {ev}")
        else:
            lines.append("  • Detection based on observed configuration state.")

        lines.extend([
            "",
            "[bold underline]RISK RATIONALE[/bold underline]",
            f"  Technical Severity:      {finding.severity.value} ({finding.severity_score}/10)",
            f"  Exploitability Score:    {finding.exploitability_score}/10",
            f"  Exposure Surface:        {finding.exposure_score}/10",
            f"  Asset Criticality Score: {finding.asset_criticality_score}/10",
            f"  Detection Confidence:    {finding.confidence_score}/10",
            f"  Calculated Risk Score:   {finding.risk_score} / 100",
            f"  Remediation Tier:        {finding.priority} — {PRIORITY_DESCRIPTIONS.get(finding.priority, '')}",
            "",
            "[bold underline]RECOMMENDED REMEDIATION[/bold underline]",
            finding.recommendation or "Review target configuration and apply vendor hardening guidelines.",
        ])

        if finding.references:
            lines.extend([
                "",
                "[bold underline]REFERENCES[/bold underline]",
            ])
            for ref in finding.references:
                lines.append(f"  - {ref}")

        return "\n".join(lines)

    def recommend_finding(self, finding: Finding) -> str:
        """Return concise remediation instructions."""
        return (
            f"Remediation Guidance for {finding.id} ({finding.title}):\n\n"
            f"Action: {finding.recommendation}\n"
            f"Target Priority: {finding.priority}\n"
            f"Target Asset: {finding.asset_id or 'General Service'}"
        )
