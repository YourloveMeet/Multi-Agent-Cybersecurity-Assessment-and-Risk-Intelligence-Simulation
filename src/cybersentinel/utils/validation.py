"""Target validation and normalization utilities."""

import ipaddress
import re
from urllib.parse import urlparse


HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
LOCAL_DOMAIN_REGEX = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-_]+)*\.local$"
)
SIMPLE_HOST_REGEX = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def normalize_target(raw_target: str) -> tuple[str, int | None]:
    """Normalize input target string into (host, port).
    
    Handles inputs like:
      - 'example.com' -> ('example.com', None)
      - 'https://example.com' -> ('example.com', 443)
      - 'http://example.com:8080' -> ('example.com', 8080)
      - '192.168.1.1:8443' -> ('192.168.1.1', 8443)
    """
    target = raw_target.strip()
    if not target:
        raise ValueError("Target cannot be empty")

    port = None

    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else (80 if parsed.scheme == "http" else None))
    else:
        # Check if port is appended e.g. host:port
        if ":" in target:
            parts = target.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                host = parts[0]
                port = int(parts[1])
            else:
                host = target
        else:
            host = target

    host = host.lower().strip()
    return host, port


def validate_target_host(host: str) -> bool:
    """Validate whether the host is a valid domain, IP, or simulation target."""
    if not host:
        return False

    # Check for localhost
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True

    # Check for valid IPv4 / IPv6
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    # Check for valid hostname or simulation domain (e.g. acme-demo.local)
    if HOSTNAME_REGEX.match(host) or LOCAL_DOMAIN_REGEX.match(host) or SIMPLE_HOST_REGEX.match(host):
        return True

    return False
