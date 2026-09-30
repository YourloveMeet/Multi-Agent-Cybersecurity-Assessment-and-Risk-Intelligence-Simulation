"""TLS and SSL configuration scanner abstraction and implementations."""

from datetime import datetime, timezone
import socket
import ssl
import time
from typing import Protocol
from pydantic import BaseModel, Field


class TLSObservation(BaseModel):
    """Normalized TLS inspection observations."""
    tls_enabled: bool
    cert_valid: bool = False
    issuer: str | None = None
    subject: str | None = None
    expires_in_days: int | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    self_signed: bool = False
    expired: bool = False
    response_time_ms: int = 0
    error: str | None = None


class TLSScanner(Protocol):
    """Protocol for TLS configuration scanners."""
    def inspect_tls(self, host: str, port: int = 443) -> TLSObservation:
        ...


class RealTLSScanner:
    """Safe, non-destructive TLS certificate and protocol scanner."""

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    def inspect_tls(self, host: str, port: int = 443) -> TLSObservation:
        start = time.perf_counter()
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_ver = ssock.version()

                    subject_dict = dict(x[0] for x in cert.get("subject", []))
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))

                    not_after_str = cert.get("notAfter", "")
                    expires_days = None
                    expired = False
                    if not_after_str:
                        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        delta = not_after - datetime.now(timezone.utc)
                        expires_days = delta.days
                        expired = expires_days <= 0

                    self_signed = subject_dict == issuer_dict
                    duration_ms = int((time.perf_counter() - start) * 1000)

                    return TLSObservation(
                        tls_enabled=True,
                        cert_valid=not expired,
                        issuer=issuer_dict.get("organizationName") or issuer_dict.get("commonName"),
                        subject=subject_dict.get("commonName") or host,
                        expires_in_days=expires_days,
                        tls_version=tls_ver,
                        cipher_suite=cipher[0] if cipher else None,
                        self_signed=self_signed,
                        expired=expired,
                        response_time_ms=duration_ms,
                    )
        except ssl.SSLCertVerificationError as e:
            # Re-attempt with unverified to fetch cert details despite certificate failure
            try:
                unverified_context = ssl._create_unverified_context()
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with unverified_context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        cipher = ssock.cipher()
                        tls_ver = ssock.version()
                        duration_ms = int((time.perf_counter() - start) * 1000)
                        return TLSObservation(
                            tls_enabled=True,
                            cert_valid=False,
                            tls_version=tls_ver,
                            cipher_suite=cipher[0] if cipher else None,
                            error=f"TLS certificate verification failed: {e.verify_message}",
                            response_time_ms=duration_ms,
                        )
            except Exception:
                duration_ms = int((time.perf_counter() - start) * 1000)
                return TLSObservation(
                    tls_enabled=True,
                    cert_valid=False,
                    error=f"TLS Certificate invalid: {str(e)}",
                    response_time_ms=duration_ms,
                )
        except Exception as e:
            duration_ms = int((time.perf_counter() - start) * 1000)
            return TLSObservation(
                tls_enabled=False,
                cert_valid=False,
                error=f"TLS handshake failed: {str(e)}",
                response_time_ms=duration_ms,
            )


class DemoTLSScanner:
    """Deterministic TLS scanner returning pre-configured TLS status."""

    def __init__(self, fixture_data: dict | None = None):
        self.data = fixture_data or {}

    def inspect_tls(self, host: str, port: int = 443) -> TLSObservation:
        tls_data = self.data.get("tls", {})
        return TLSObservation(
            tls_enabled=tls_data.get("tls_enabled", True),
            cert_valid=tls_data.get("cert_valid", True),
            issuer=tls_data.get("issuer", "Let's Encrypt Authority X3"),
            subject=tls_data.get("subject", host),
            expires_in_days=tls_data.get("expires_in_days", 12),
            tls_version=tls_data.get("tls_version", "TLSv1.1"),
            cipher_suite=tls_data.get("cipher_suite", "ECDHE-RSA-AES128-SHA"),
            self_signed=tls_data.get("self_signed", False),
            expired=tls_data.get("expired", False),
            response_time_ms=18,
        )
