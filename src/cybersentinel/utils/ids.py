"""ID generation utilities for assessments, findings, and assets."""

from datetime import datetime
import uuid


def generate_assessment_id(prefix: str = "ASM") -> str:
    """Generate a readable assessment ID like ASM-20260930-001 or ASM-20260930-A1B2."""
    date_str = datetime.utcnow().strftime("%Y%m%d")
    short_uuid = uuid.uuid4().hex[:4].upper()
    return f"{prefix}-{date_str}-{short_uuid}"


def generate_finding_id(index: int) -> str:
    """Generate a formatted finding ID like FIND-001."""
    return f"FIND-{index:03d}"


def generate_asset_id(index: int) -> str:
    """Generate a formatted asset ID like AST-001."""
    return f"AST-{index:03d}"
