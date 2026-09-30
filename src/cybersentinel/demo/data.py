"""Demo fixture loaders and synthetic data generators."""

import json
from pathlib import Path
from typing import Any


def load_demo_target_data() -> dict[str, Any]:
    """Load standard demo target JSON data."""
    # Try finding standard_target.json relative to this file or workspace root
    possible_paths = [
        Path(__file__).resolve().parent.parent.parent.parent / "data" / "demo" / "standard_target.json",
        Path("data/demo/standard_target.json"),
    ]

    for p in possible_paths:
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)

    # Fallback inline mock data if file not found
    return {
        "target": {"host": "acme-demo.local", "mode": "simulation", "profile": "standard", "authorized": True},
        "dns": {"resolved": True, "ip_addresses": ["198.51.100.42"], "canonical_name": "acme-demo.local", "response_time_ms": 12},
        "assets": [
            {"id": "AST-001", "name": "Public Web Server", "asset_type": "web-server", "host": "acme-demo.local", "port": 443, "exposure": "internet", "environment": "production", "criticality": "high", "criticality_score": 8},
            {"id": "AST-003", "name": "Internal Admin Service", "asset_type": "admin-portal", "host": "acme-demo.local", "port": 8080, "exposure": "internet", "environment": "production", "criticality": "critical", "criticality_score": 10},
        ],
        "ports": [
            {"port": 80, "is_open": True, "service": "http"},
            {"port": 443, "is_open": True, "service": "https"},
            {"port": 8080, "is_open": True, "service": "http-admin"},
        ],
        "http": {
            "reachable": True,
            "status_code": 200,
            "headers": {"server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3"},
            "cookies": [{"name": "SESSIONID", "value": "demo", "secure": True, "httponly": False, "samesite": None}],
            "redirects": [],
            "redirects_to_https": false,
            "server_header": "Apache/2.4.41 (Ubuntu)",
            "x_powered_by": "PHP/7.4.3",
            "has_hsts": False,
            "has_csp": False,
            "has_x_content_type_options": False,
            "has_x_frame_options": False,
            "has_referrer_policy": False,
            "has_permissions_policy": False,
        },
        "tls": {
            "tls_enabled": True,
            "cert_valid": True,
            "issuer": "Let's Encrypt Authority X3",
            "subject": "acme-demo.local",
            "expires_in_days": 12,
            "tls_version": "TLSv1.1",
            "cipher_suite": "ECDHE-RSA-AES128-SHA",
            "self_signed": False,
            "expired": False,
        },
    }
