"""JSON export formatter for machine-readable assessment integration."""

import json
from typing import Any
from cybersentinel.models.assessment import AssessmentContext


class JSONExportGenerator:
    """Produces structured machine-readable JSON representations of assessments."""

    def to_dict(self, context: AssessmentContext) -> dict[str, Any]:
        """Convert AssessmentContext into a standardized JSON-compatible dict."""
        return {
            "assessment": {
                "id": context.assessment_id,
                "target": context.target.display_name,
                "mode": context.mode,
                "profile": context.profile,
                "overall_risk": context.overall_risk,
                "risk_score": context.risk_score,
                "started_at": context.started_at.isoformat(),
                "completed_at": context.completed_at.isoformat() if context.completed_at else None,
                "duration_seconds": context.duration_seconds,
            },
            "agents": [
                {
                    "agent_name": ar.agent_name,
                    "status": ar.status,
                    "duration_ms": ar.duration_ms,
                    "finding_count": len(ar.findings),
                    "errors": ar.errors,
                    "observations": ar.observations,
                }
                for ar in context.agent_results
            ],
            "assets": [
                {
                    "id": a.id,
                    "name": a.name,
                    "asset_type": a.asset_type,
                    "host": a.host,
                    "port": a.port,
                    "exposure": a.exposure,
                    "environment": a.environment,
                    "criticality": a.criticality,
                    "criticality_score": a.criticality_score,
                }
                for a in context.assets
            ],
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity.value,
                    "risk_score": f.risk_score,
                    "priority": f.priority,
                    "asset_id": f.asset_id,
                    "description": f.description,
                    "impact": f.impact,
                    "recommendation": f.recommendation,
                    "evidence": f.evidence,
                    "references": f.references,
                    "scores": {
                        "severity": f.severity_score,
                        "exploitability": f.exploitability_score,
                        "exposure": f.exposure_score,
                        "asset_criticality": f.asset_criticality_score,
                        "confidence": f.confidence_score,
                    },
                    "source_agent": f.source_agent,
                }
                for f in context.findings
            ],
            "recommendations": [
                {
                    "priority": f.priority,
                    "finding_id": f.id,
                    "title": f.title,
                    "action": f.recommendation,
                    "target_asset": f.asset_id,
                }
                for f in context.findings
            ],
        }

    def generate(self, context: AssessmentContext, indent: int = 2) -> str:
        """Serialize assessment context to formatted JSON string."""
        return json.dumps(self.to_dict(context), indent=indent, default=str)
