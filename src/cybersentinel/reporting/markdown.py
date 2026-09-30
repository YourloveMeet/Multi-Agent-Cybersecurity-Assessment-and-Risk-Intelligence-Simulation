"""Markdown report generator conforming to standard assessment documentation."""

from datetime import datetime
from cybersentinel.models.assessment import AssessmentContext
from cybersentinel.risk.prioritization import PRIORITY_DESCRIPTIONS


class MarkdownReportGenerator:
    """Generates professional Markdown assessment reports."""

    def generate(self, context: AssessmentContext) -> str:
        completed = context.completed_at or datetime.utcnow()
        completed_str = completed.strftime("%Y-%m-%d %H:%M:%S UTC")
        started_str = context.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")

        lines: list[str] = [
            f"# CyberSentinel Security Assessment Report",
            f"**Assessment ID:** `{context.assessment_id}`  ",
            f"**Generated:** {completed_str}  ",
            f"**Assessment Mode:** {context.mode.capitalize()}  ",
            f"**Profile:** {context.profile.capitalize()}",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"- **Target Host:** `{context.target.display_name}`",
            f"- **Overall Risk Level:** **{context.overall_risk}**",
            f"- **Overall Risk Score:** **{context.risk_score} / 100**",
            f"- **Total Discovered Findings:** {len(context.findings)}",
            f"- **Discovered Assets:** {len(context.assets)}",
            f"- **Scan Duration:** {context.duration_seconds:.2f} seconds",
            "",
            "### Finding Breakdown by Severity",
            "",
            "| Severity | Count |",
            "|:---|:---:|",
        ]

        counts = context.severity_counts
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            lines.append(f"| {sev} | {counts.get(sev, 0)} |")

        lines.extend([
            "",
            "---",
            "",
            "## 2. Assessment Scope",
            "",
            f"- **Target URL:** {context.target.url}",
            f"- **Target IP:** {context.target.ip or 'N/A'}",
            f"- **Port:** {context.target.port or (443 if context.target.scheme == 'https' else 80)}",
            f"- **Authorization Confirmed:** {'Yes (Authorized Scan)' if context.authorized else 'Simulation Mode'}",
            f"- **Scan Profile:** {context.profile}",
            "",
            "---",
            "",
            "## 3. Discovered Asset Inventory",
            "",
            "| Asset ID | Name | Type | Host:Port | Criticality | Exposure |",
            "|:---|:---|:---|:---|:---:|:---|",
        ])

        for a in context.assets:
            host_port = f"{a.host or context.target.host}:{a.port or '-'}"
            lines.append(f"| `{a.id}` | {a.name} | {a.asset_type} | `{host_port}` | {a.criticality.upper()} ({a.criticality_score}/10) | {a.exposure} |")

        lines.extend([
            "",
            "---",
            "",
            "## 4. Multi-Agent Pipeline Summary",
            "",
            "| Agent Name | Status | Duration | Findings |",
            "|:---|:---:|:---:|:---:|",
        ])

        for ar in context.agent_results:
            lines.append(f"| {ar.agent_name} | {ar.status.upper()} | {ar.duration_ms}ms | {len(ar.findings)} |")

        lines.extend([
            "",
            "---",
            "",
            "## 5. Security Findings",
            "",
        ])

        if not context.findings:
            lines.append("No security vulnerabilities or configuration defects identified.")
        else:
            for f in context.findings:
                lines.extend([
                    f"### [{f.id}] {f.title}",
                    "",
                    f"- **Severity:** `{f.severity.value}` (Base: {f.severity_score}/10)",
                    f"- **Risk Score:** `{f.risk_score} / 100`",
                    f"- **Remediation Priority:** `{f.priority}` ({PRIORITY_DESCRIPTIONS.get(f.priority, '')})",
                    f"- **Category:** {f.category}",
                    f"- **Target Asset:** `{f.asset_id or 'General'}`",
                    f"- **Detection Source:** {f.source_agent}",
                    "",
                    "#### Description",
                    f"{f.description}",
                    "",
                    "#### Observed Evidence",
                ])
                if f.evidence:
                    for ev in f.evidence:
                        lines.append(f"- {ev}")
                else:
                    lines.append("- Observed via active inspection.")

                lines.extend([
                    "",
                    "#### Impact",
                    f"{f.impact or 'Potential compromise of confidentiality, integrity, or availability.'}",
                    "",
                    "#### Actionable Remediation",
                    f"{f.recommendation or 'Implement vendor hardening recommendations.'}",
                    "",
                ])

                if f.references:
                    lines.append("#### References")
                    for ref in f.references:
                        lines.append(f"- {ref}")
                    lines.append("")

        lines.extend([
            "---",
            "",
            "## 6. Prioritized Remediation Queue",
            "",
            "| Priority | Finding ID | Title | Risk Score | Recommended Action |",
            "|:---:|:---|:---|:---:|:---|",
        ])

        for f in context.findings:
            rec_snippet = (f.recommendation[:75] + "...") if len(f.recommendation) > 75 else f.recommendation
            lines.append(f"| **{f.priority}** | `{f.id}` | {f.title} | {f.risk_score} | {rec_snippet} |")

        lines.extend([
            "",
            "---",
            "",
            "## 7. Methodology & Limitations",
            "",
            "### Methodology",
            "CyberSentinel executes an autonomous multi-agent pipeline conducting non-destructive inspection. "
            "Findings from reconnaissance, web security, and configuration audits are deduplicated, normalized, "
            "and evaluated by a deterministic risk intelligence engine correlating technical severity with asset criticality.",
            "",
            "### Limitations",
            "This assessment performs non-destructive configuration, transport, and exposure checks only. "
            "It does not perform active exploit verification, penetration testing, source code analysis, "
            "or denial-of-service simulations. Absence of findings does not guarantee complete security.",
            "",
            "---",
            f"*CyberSentinel Automated Assessment Platform — End of Report (`{context.assessment_id}`)*",
        ])

        return "\n".join(lines)
