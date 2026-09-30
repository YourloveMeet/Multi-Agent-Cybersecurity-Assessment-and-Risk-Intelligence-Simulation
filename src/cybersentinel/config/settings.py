"""Configuration management and settings persistence."""

from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # Python 3.10 fallback


class ScannerConfig(BaseModel):
    timeout: float = 5.0
    verify_tls: bool = True
    max_redirects: int = 5
    default_ports: list[int] = Field(default_factory=lambda: [22, 80, 443, 8080, 8443])


class AssessmentConfig(BaseModel):
    default_profile: str = "standard"
    require_authorization: bool = True


class OutputConfig(BaseModel):
    reports_dir: str = "./reports"
    save_history: bool = True


class Settings(BaseModel):
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    assessment: AssessmentConfig = Field(default_factory=AssessmentConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    @classmethod
    def get_config_dir(cls) -> Path:
        """Return base directory path ~/.cybersentinel."""
        p = Path.home() / ".cybersentinel"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @classmethod
    def get_config_file_path(cls) -> Path:
        """Return path to config.toml."""
        return cls.get_config_dir() / "config.toml"

    @classmethod
    def load(cls) -> "Settings":
        """Load configuration from ~/.cybersentinel/config.toml or return default."""
        config_path = cls.get_config_file_path()
        if config_path.exists():
            try:
                with open(config_path, "rb") as f:
                    data = tomllib.load(f)
                return cls(**data)
            except Exception:
                pass
        return cls()

    def to_toml(self) -> str:
        """Format settings as clean TOML string."""
        ports_str = ", ".join(str(p) for p in self.scanner.default_ports)
        return (
            "[scanner]\n"
            f"timeout = {self.scanner.timeout}\n"
            f"verify_tls = {str(self.scanner.verify_tls).lower()}\n"
            f"max_redirects = {self.scanner.max_redirects}\n"
            f"default_ports = [{ports_str}]\n\n"
            "[assessment]\n"
            f'default_profile = "{self.assessment.default_profile}"\n'
            f"require_authorization = {str(self.assessment.require_authorization).lower()}\n\n"
            "[output]\n"
            f'reports_dir = "{self.output.reports_dir}"\n'
            f"save_history = {str(self.output.save_history).lower()}\n"
        )
