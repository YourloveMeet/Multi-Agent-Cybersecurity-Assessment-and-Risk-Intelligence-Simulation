"""Asset model for inventory and business context mapping."""

from pydantic import BaseModel, Field


class Asset(BaseModel):
    """Network, service, or system asset within the assessment boundary."""
    id: str = Field(description="Unique asset identifier, e.g. AST-001")
    name: str = Field(description="Descriptive asset name")
    asset_type: str = Field(default="service", description="e.g. web-server, api, database, auth-service")

    host: str | None = None
    port: int | None = None

    exposure: str = Field(default="internet", description="internet, internal, dmz, or restricted")
    environment: str = Field(default="production", description="production, staging, or development")

    criticality: str = Field(default="medium", description="critical, high, medium, or low")
    criticality_score: int = Field(default=5, ge=1, le=10, description="Asset business criticality rating (1-10)")

    description: str | None = None
