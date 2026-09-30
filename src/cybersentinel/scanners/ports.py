"""Port and service exposure scanner abstraction and implementations."""

import socket
import time
from typing import Protocol
from pydantic import BaseModel, Field

DEFAULT_SAFE_PORTS = [22, 80, 443, 8080, 8443]

KNOWN_SERVICE_NAMES = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    443: "https",
    8080: "http-admin",
    8443: "https-admin",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
}


class PortResult(BaseModel):
    """Result of a safe port connectivity check."""
    port: int
    is_open: bool
    service: str
    banner: str | None = None
    response_time_ms: int = 0
    error: str | None = None


class PortScanner(Protocol):
    """Protocol for port checking scanners."""
    def scan_ports(self, host: str, ports: list[int] | None = None) -> list[PortResult]:
        ...


class RealPortScanner:
    """Safe, non-destructive port connectivity scanner restricted to safe ports."""

    def __init__(self, timeout: float = 1.5):
        self.timeout = timeout

    def scan_ports(self, host: str, ports: list[int] | None = None) -> list[PortResult]:
        target_ports = ports or DEFAULT_SAFE_PORTS
        results: list[PortResult] = []

        for port in target_ports:
            start = time.perf_counter()
            is_open = False
            banner = None
            err = None

            try:
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    is_open = True
                    # Optionally receive up to 128 bytes banner if sent by service
                    try:
                        sock.settimeout(0.5)
                        data = sock.recv(128)
                        if data:
                            banner = data.decode("utf-8", errors="replace").strip()
                    except (socket.timeout, OSError):
                        pass
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                is_open = False
                err = str(e)

            duration_ms = int((time.perf_counter() - start) * 1000)
            service_name = KNOWN_SERVICE_NAMES.get(port, f"service-{port}")

            results.append(
                PortResult(
                    port=port,
                    is_open=is_open,
                    service=service_name,
                    banner=banner,
                    response_time_ms=duration_ms,
                    error=err if not is_open else None,
                )
            )

        return results


class DemoPortScanner:
    """Deterministic port scanner using preset simulation fixture."""

    def __init__(self, fixture_data: dict | None = None):
        self.data = fixture_data or {}

    def scan_ports(self, host: str, ports: list[int] | None = None) -> list[PortResult]:
        raw_ports = self.data.get("ports", [])
        results: list[PortResult] = []

        for p_info in raw_ports:
            port_num = p_info["port"]
            if ports and port_num not in ports:
                continue
            results.append(
                PortResult(
                    port=port_num,
                    is_open=p_info.get("is_open", False),
                    service=p_info.get("service", KNOWN_SERVICE_NAMES.get(port_num, f"svc-{port_num}")),
                    banner=p_info.get("banner"),
                    response_time_ms=10,
                )
            )
        return results
