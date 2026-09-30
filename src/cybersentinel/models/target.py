"""Target data model for assessments."""

from typing import Literal
from pydantic import BaseModel, Field


class Target(BaseModel):
    """Specification of an assessment target."""
    host: str
    port: int | None = None
    ip: str | None = None
    scheme: str = "https"
    mode: Literal["authorized", "simulation"] = "authorized"
    profile: Literal["standard", "quick"] = "standard"
    authorized: bool = Field(default=False, description="Must be confirmed true for real live scans")

    @property
    def display_name(self) -> str:
        """Formatted target host representation."""
        if self.port and self.port not in (80, 443):
            return f"{self.host}:{self.port}"
        return self.host

    @property
    def url(self) -> str:
        """Full URL representation."""
        base = f"{self.scheme}://{self.host}"
        if self.port and not ((self.scheme == "http" and self.port == 80) or (self.scheme == "https" and self.port == 443)):
            base += f":{self.port}"
        return base
