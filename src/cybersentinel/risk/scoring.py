"""Deterministic risk scoring calculation and categorization."""

from typing import Literal
from cybersentinel.models.asset import Asset
from cybersentinel.models.finding import Finding
from cybersentinel.risk.severity import Severity

RiskCategory = Literal["LOW", "MODERATE", "HIGH", "CRITICAL"]


def calculate_finding_risk(
    finding: Finding,
    asset: Asset | None = None,
) -> tuple[float, RiskCategory]:
    """Calculate deterministic risk score and category for an individual finding.
    
    Formula based on weighted combination:
      - Technical Severity: 35%
      - Exploitability: 20%
      - Exposure Surface: 20%
      - Asset Criticality: 25%
    
    Each component is on a 1-10 scale. Total is multiplied by 10 to give a 0-100 scale.
    """
    severity_val = finding.severity_score if finding.severity_score > 0 else finding.severity.score
    exploitability_val = finding.exploitability_score
    exposure_val = finding.exposure_score

    # Use asset criticality if asset is provided and finding's asset_criticality is default/override
    if asset:
        asset_crit_val = asset.criticality_score
    else:
        asset_crit_val = finding.asset_criticality_score

    # Ensure all inputs are bounded [1, 10]
    s = max(1, min(10, severity_val))
    e = max(1, min(10, exploitability_val))
    x = max(1, min(10, exposure_val))
    a = max(1, min(10, asset_crit_val))

    raw_score = (s * 0.35 + e * 0.20 + x * 0.20 + a * 0.25) * 10.0

    # Optional slight confidence adjustment: ± 5% based on confidence score (1-10)
    conf_factor = 0.95 + (finding.confidence_score / 10.0) * 0.10  # 0.96 to 1.05
    score = raw_score * conf_factor

    # Strictly clamp to [0.0, 100.0]
    score = round(max(0.0, min(100.0, score)), 1)
    category = get_risk_category(score)

    return score, category


def get_risk_category(score: float) -> RiskCategory:
    """Classify a 0-100 risk score into standard risk tier."""
    if score >= 75.0:
        return "CRITICAL"
    elif score >= 50.0:
        return "HIGH"
    elif score >= 25.0:
        return "MODERATE"
    else:
        return "LOW"


def calculate_overall_risk(findings: list[Finding]) -> tuple[float, RiskCategory]:
    """Compute holistic assessment risk score from findings.
    
    If no findings exist, returns (0.0, 'LOW').
    Uses a weighted combination of top critical findings with dampening to ensure
    high-severity issues drive the score while preventing false inflation.
    """
    if not findings:
        return 0.0, "LOW"

    # Sort finding risk scores descending
    scores = sorted([f.risk_score for f in findings], reverse=True)

    # Top risk drives 60% of score, next top-3 drive 30%, average of rest drives 10%
    top_score = scores[0]
    if len(scores) == 1:
        composite = top_score
    elif len(scores) <= 4:
        secondary = sum(scores[1:]) / len(scores[1:])
        composite = top_score * 0.70 + secondary * 0.30
    else:
        top_secondary = sum(scores[1:4]) / 3.0
        remaining = sum(scores[4:]) / len(scores[4:])
        composite = top_score * 0.60 + top_secondary * 0.30 + remaining * 0.10

    overall_score = round(max(0.0, min(100.0, composite)), 1)
    category = get_risk_category(overall_score)
    return overall_score, category
