"""Core domain exception classes."""


class CyberSentinelError(Exception):
    """Base exception for all CyberSentinel domain errors."""
    pass


class TargetValidationError(CyberSentinelError):
    """Raised when target host, IP or port fails validation."""
    pass


class AuthorizationRequiredError(CyberSentinelError):
    """Raised when an unauthorized scan is attempted without confirmation."""
    pass


class ScannerExecutionError(CyberSentinelError):
    """Raised when a network or scanner operation encounters a fatal fault."""
    pass


class AgentExecutionError(CyberSentinelError):
    """Raised when an agent execution fails critically."""
    pass


class StorageError(CyberSentinelError):
    """Raised when persisting or loading assessment records fails."""
    pass
