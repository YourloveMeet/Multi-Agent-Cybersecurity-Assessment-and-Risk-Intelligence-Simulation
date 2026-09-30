"""Assessment persistence repository for history and exports."""

from datetime import datetime
import json
from pathlib import Path
from typing import Any

from cybersentinel.models.assessment import AssessmentContext
from cybersentinel.reporting.json_export import JSONExportGenerator
from cybersentinel.reporting.markdown import MarkdownReportGenerator


class AssessmentRepository:
    """Manages saving and loading assessment snapshots from ~/.cybersentinel/history/."""

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir or (Path.home() / ".cybersentinel")
        self.history_dir = self.base_dir / "history"
        self.history_dir.mkdir(parents=True, exist_ok=True)

    def save_assessment(self, context: AssessmentContext) -> Path:
        """Save assessment state as JSON file in history directory."""
        export_dict = JSONExportGenerator().to_dict(context)
        file_path = self.history_dir / f"{context.assessment_id}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(export_dict, f, indent=2, default=str)
        return file_path

    def list_history(self) -> list[dict[str, Any]]:
        """List all previous assessment summaries from history."""
        records: list[dict[str, Any]] = []
        if not self.history_dir.exists():
            return records

        for file_path in sorted(self.history_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    asm = data.get("assessment", {})
                    records.append({
                        "id": asm.get("id", file_path.stem),
                        "target": asm.get("target", "Unknown"),
                        "mode": asm.get("mode", "authorized"),
                        "overall_risk": asm.get("overall_risk", "UNKNOWN"),
                        "risk_score": asm.get("risk_score", 0.0),
                        "started_at": asm.get("started_at", ""),
                        "findings_count": len(data.get("findings", [])),
                        "file_path": str(file_path),
                    })
            except Exception:
                continue

        return records

    def export_reports(
        self,
        context: AssessmentContext,
        target_dir: str | Path = "./reports",
    ) -> tuple[Path, Path]:
        """Export Markdown report and JSON file to destination directory."""
        out_dir = Path(target_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        md_path = out_dir / f"assessment-{context.assessment_id}.md"
        json_path = out_dir / f"assessment-{context.assessment_id}.json"

        md_content = MarkdownReportGenerator().generate(context)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        json_content = JSONExportGenerator().generate(context)
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(json_content)

        return md_path, json_path
