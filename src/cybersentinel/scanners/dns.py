"""DNS and host resolution scanner abstraction and implementations."""

import socket
import time
from typing import Protocol
from pydantic import BaseModel, Field

try:
    import dns.resolver
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False


class DNSResult(BaseModel):
    """Normalized DNS resolution outcome."""
    resolved: bool
    ip_addresses: list[str] = Field(default_factory=list)
    canonical_name: str | None = None
    response_time_ms: int = 0
    error: str | None = None


class DNSScanner(Protocol):
    """Protocol for DNS and name resolution scanners."""
    def resolve(self, host: str) -> DNSResult:
        ...


class RealDNSScanner:
    """Safe, live DNS resolution using dnspython with socket fallback."""

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    def resolve(self, host: str) -> DNSResult:
        start = time.perf_counter()
        ips: list[str] = []
        cname = None

        # Check if already IP address
        try:
            socket.inet_aton(host)
            duration_ms = int((time.perf_counter() - start) * 1000)
            return DNSResult(
                resolved=True,
                ip_addresses=[host],
                canonical_name=host,
                response_time_ms=duration_ms,
            )
        except OSError:
            pass

        if HAVE_DNSPYTHON:
            try:
                resolver = dns.resolver.Resolver()
                resolver.lifetime = self.timeout
                resolver.timeout = self.timeout
                answers = resolver.resolve(host, "A")
                for rdata in answers:
                    ips.append(rdata.to_text())
                cname = str(answers.canonical_name).rstrip(".")
            except Exception:
                pass

        # Fallback to standard library getaddrinfo
        if not ips:
            try:
                addr_info = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
                for item in addr_info:
                    ip = item[4][0]
                    if ip not in ips:
                        ips.append(ip)
            except Exception as e:
                duration_ms = int((time.perf_counter() - start) * 1000)
                return DNSResult(
                    resolved=False,
                    error=f"DNS resolution failed: {str(e)}",
                    response_time_ms=duration_ms,
                )

        duration_ms = int((time.perf_counter() - start) * 1000)
        return DNSResult(
            resolved=bool(ips),
            ip_addresses=ips,
            canonical_name=cname or host,
            response_time_ms=duration_ms,
        )


class DemoDNSScanner:
    """Deterministic synthetic DNS scanner for demo mode."""

    def __init__(self, fixture_data: dict | None = None):
        self.data = fixture_data or {}

    def resolve(self, host: str) -> DNSResult:
        dns_info = self.data.get("dns", {})
        return DNSResult(
            resolved=dns_info.get("resolved", True),
            ip_addresses=dns_info.get("ip_addresses", ["198.51.100.42", "198.51.100.43"]),
            canonical_name=dns_info.get("canonical_name", host),
            response_time_ms=dns_info.get("response_time_ms", 15),
        )
