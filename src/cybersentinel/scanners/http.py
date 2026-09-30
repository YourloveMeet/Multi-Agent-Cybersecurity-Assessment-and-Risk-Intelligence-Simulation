"""HTTP and Web application security scanner abstraction and implementations."""

import time
from typing import Any, Protocol
from pydantic import BaseModel, Field
import httpx

from cybersentinel.models.target import Target


class CookieInfo(BaseModel):
    """Normalized cookie attributes."""
    name: str
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None


class HTTPObservation(BaseModel):
    """Observation resulting from safe HTTP/HTTPS inspection."""
    reachable: bool
    status_code: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: list[CookieInfo] = Field(default_factory=list)

    redirects: list[str] = Field(default_factory=list)
    redirects_to_https: bool = False

    server_header: str | None = None
    x_powered_by: str | None = None

    has_hsts: bool = False
    has_csp: bool = False
    has_x_content_type_options: bool = False
    has_x_frame_options: bool = False
    has_referrer_policy: bool = False
    has_permissions_policy: bool = False

    response_time_ms: int = 0
    error: str | None = None


class HTTPScanner(Protocol):
    """Protocol for web security HTTP scanners."""
    def inspect(self, target: Target) -> HTTPObservation:
        ...


class RealHTTPScanner:
    """Safe, non-destructive HTTP/HTTPS scanner using httpx."""

    def __init__(self, timeout: float = 5.0, verify_tls: bool = True):
        self.timeout = timeout
        self.verify_tls = verify_tls

    def inspect(self, target: Target) -> HTTPObservation:
        start = time.perf_counter()
        headers_lower: dict[str, str] = {}
        cookies_list: list[CookieInfo] = []
        redirects: list[str] = []
        redirects_to_https = False
        status_code = None
        server_header = None
        x_powered_by = None
        err = None
        reachable = False

        # 1. First probe plain HTTP to inspect redirect behavior
        try:
            http_url = f"http://{target.host}"
            if target.port and target.port == 8080:
                http_url = f"http://{target.host}:8080"
            with httpx.Client(timeout=self.timeout, follow_redirects=True, verify=self.verify_tls) as client:
                res = client.get(http_url)
                if res.history:
                    for h in res.history:
                        redirects.append(str(h.url))
                        if str(h.headers.get("location", "")).startswith("https://"):
                            redirects_to_https = True
                if str(res.url).startswith("https://"):
                    redirects_to_https = True
        except Exception:
            pass

        # 2. Probe HTTPS endpoint for security headers and cookies
        https_url = f"https://{target.host}"
        if target.port and target.port not in (80, 443):
            https_url = f"https://{target.host}:{target.port}"

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True, verify=self.verify_tls) as client:
                resp = client.get(https_url)
                reachable = True
                status_code = resp.status_code
                for k, v in resp.headers.items():
                    headers_lower[k.lower()] = v

                server_header = headers_lower.get("server")
                x_powered_by = headers_lower.get("x-powered-by")

                # Parse cookies
                for c in resp.cookies.jar:
                    cookies_list.append(
                        CookieInfo(
                            name=c.name,
                            secure=bool(c.secure),
                            httponly=bool(c.has_nonstandard_attr("httponly") or c.has_nonstandard_attr("HttpOnly")),
                            samesite=getattr(c, "samesite", None),
                        )
                    )
        except Exception as e:
            err = f"HTTPS inspection encountered error: {str(e)}"
            # If HTTPS failed, check if plain HTTP was reachable
            if redirects:
                reachable = True

        duration_ms = int((time.perf_counter() - start) * 1000)

        # Header presence checks
        has_hsts = "strict-transport-security" in headers_lower
        has_csp = "content-security-policy" in headers_lower
        has_x_content_type = "x-content-type-options" in headers_lower
        has_x_frame = "x-frame-options" in headers_lower
        has_referrer = "referrer-policy" in headers_lower
        has_permissions = "permissions-policy" in headers_lower or "feature-policy" in headers_lower

        return HTTPObservation(
            reachable=reachable,
            status_code=status_code,
            headers=headers_lower,
            cookies=cookies_list,
            redirects=redirects,
            redirects_to_https=redirects_to_https,
            server_header=server_header,
            x_powered_by=x_powered_by,
            has_hsts=has_hsts,
            has_csp=has_csp,
            has_x_content_type_options=has_x_content_type,
            has_x_frame_options=has_x_frame,
            has_referrer_policy=has_referrer,
            has_permissions_policy=has_permissions,
            response_time_ms=duration_ms,
            error=err,
        )


class DemoHTTPScanner:
    """Deterministic HTTP scanner returning pre-configured observations."""

    def __init__(self, fixture_data: dict | None = None):
        self.data = fixture_data or {}

    def inspect(self, target: Target) -> HTTPObservation:
        http_data = self.data.get("http", {})
        raw_cookies = http_data.get("cookies", [])
        cookie_models = [CookieInfo(**c) for c in raw_cookies]

        return HTTPObservation(
            reachable=http_data.get("reachable", True),
            status_code=http_data.get("status_code", 200),
            headers=http_data.get("headers", {}),
            cookies=cookie_models,
            redirects=http_data.get("redirects", []),
            redirects_to_https=http_data.get("redirects_to_https", False),
            server_header=http_data.get("server_header", "Apache/2.4.41 (Ubuntu)"),
            x_powered_by=http_data.get("x_powered_by", "PHP/7.4.3"),
            has_hsts=http_data.get("has_hsts", False),
            has_csp=http_data.get("has_csp", False),
            has_x_content_type_options=http_data.get("has_x_content_type_options", False),
            has_x_frame_options=http_data.get("has_x_frame_options", False),
            has_referrer_policy=http_data.get("has_referrer_policy", False),
            has_permissions_policy=http_data.get("has_permissions_policy", False),
            response_time_ms=25,
        )
