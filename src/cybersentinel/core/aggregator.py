"""Finding aggregator and deduplication pipeline."""

import re
from cybersentinel.models.finding import Finding
from cybersentinel.risk.severity import Severity
from cybersentinel.utils.ids import generate_finding_id


def _normalize_title(title: str) -> str:
    """Normalize finding title for fuzzy deduplication."""
    # Convert to lowercase and strip punctuation/extra whitespace
    clean = re.sub(r"[^a-zA-Z0-9\s]", "", title.lower())
    return " ".join(clean.split())


def aggregate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate and merge findings from multiple agents.
    
    Findings with the same (normalized_category, normalized_title, asset_id) are merged:
      - Evidence items are united without duplicates.
      - References are united.
      - Highest severity and severity_score are retained.
      - Maximum exploitability, exposure, and asset criticality scores are retained.
      - Re-indexes findings with clean identifiers (FIND-001, FIND-002, etc.).
    """
    if not findings:
        return []

    grouped: dict[tuple[str, str, str | None], list[Finding]] = {}

    for finding in findings:
        norm_cat = finding.category.strip().lower()
        norm_title = _normalize_title(finding.title)
        key = (norm_cat, norm_title, finding.asset_id)
        grouped.setdefault(key, []).append(finding)

    merged_findings: list[Finding] = []
    finding_counter = 1

    for (norm_cat, norm_title, asset_id), group in grouped.items():
        if len(group) == 1:
            base = group[0].model_copy(deep=True)
            base.id = generate_finding_id(finding_counter)
            merged_findings.append(base)
            finding_counter += 1
            continue

        # Multiple findings to merge
        primary = group[0].model_copy(deep=True)

        combined_evidence: list[str] = []
        combined_refs: list[str] = []
        max_sev_score = primary.severity_score
        highest_severity = primary.severity
        max_exploit = primary.exploitability_score
        max_exposure = primary.exposure_score
        max_asset_crit = primary.asset_criticality_score
        max_confidence = primary.confidence_score
        source_agents = set()

        for f in group:
            source_agents.add(f.source_agent)
            for ev in f.evidence:
                if ev not in combined_evidence:
                    combined_evidence.append(ev)
            for ref in f.references:
                if ref not in combined_refs:
                    combined_refs.append(ref)

            if f.severity_score > max_sev_score:
                max_sev_score = f.severity_score
                highest_severity = f.severity
            elif f.severity.score > highest_severity.score:
                highest_severity = f.severity
                max_sev_score = f.severity_score

            max_exploit = max(max_exploit, f.exploitability_score)
            max_exposure = max(max_exposure, f.exposure_score)
            max_asset_crit = max(max_asset_crit, f.asset_criticality_score)
            max_confidence = max(max_confidence, f.confidence_score)

        primary.id = generate_finding_id(finding_counter)
        primary.severity = highest_severity
        primary.severity_score = max_sev_score
        primary.exploitability_score = max_exploit
        primary.exposure_score = max_exposure
        primary.asset_criticality_score = max_asset_crit
        primary.confidence_score = max_confidence
        primary.evidence = combined_evidence
        primary.references = combined_refs
        primary.source_agent = ", ".join(sorted(source_agents))

        merged_findings.append(primary)
        finding_counter += 1

    return merged_findings
