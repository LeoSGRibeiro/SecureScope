"""
Shared anti-SSRF host validation and severity color palette,
mirrored from backend/app/schemas/target.py and frontend/src/types/index.ts
so the desktop app refuses internal/private targets before scanning.
"""
import ipaddress
from urllib.parse import urlparse

BLOCKED_HOSTS = {
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    "169.254.169.254",
    "metadata.google.internal",
}

SEVERITY_COLORS = {
    "critical": "#f87171",
    "high": "#fb923c",
    "medium": "#facc15",
    "low": "#60a5fa",
    "informational": "#9ca3af",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


def extract_host(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"//{url}")
    return parsed.hostname or url.split("/")[0].split(":")[0]


def is_blocked_target(url: str) -> bool:
    host = extract_host(url).lower()
    if not host:
        return True
    if host in BLOCKED_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return True
    except ValueError:
        pass
    return False
