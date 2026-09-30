"""Severity enumeration and weight definitions."""

from enum import Enum


class Severity(str, Enum):
    """Vulnerability and finding severity ratings."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def score(self) -> int:
        """Map severity to numeric base score."""
        scores = {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 5,
            Severity.HIGH: 8,
            Severity.CRITICAL: 10,
        }
        return scores[self]

    @property
    def color(self) -> str:
        """Rich terminal color / style representation."""
        styles = {
            Severity.INFO: "dim",
            Severity.LOW: "cyan",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "red",
            Severity.CRITICAL: "bold red",
        }
        return styles[self]

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        """Safely parse severity string case-insensitively."""
        normalized = value.strip().upper()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.INFO


SEVERITY_STYLES = {
    "INFO": "dim",
    "LOW": "cyan",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold red",
}
