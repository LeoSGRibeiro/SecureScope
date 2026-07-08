"""
Hosting/network-org lookup: resolves the target host to an IP address and
queries ipinfo.io (free tier, no token required) for the owning
organization/ASN — used as a fallback hosting signal when no CDN/cloud
header (Cloudflare, CloudFront, Azure, etc.) was detected in
fingerprint_scanner.py. Best-effort only: any failure (DNS resolution,
timeout, rate limit) is swallowed and simply yields no hosting info.
"""
import asyncio
import socket
from urllib.parse import urlparse
import httpx

IPINFO_URL = "https://ipinfo.io/{ip}/json"


def _extract_host(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"//{url}", scheme="")
    return (parsed.hostname or "").lower()


async def resolve_hosting_org(url: str, timeout: float = 8.0) -> dict | None:
    """Returns {"ip": str, "org": str, "country": str} or None on any failure."""
    host = _extract_host(url)
    if not host:
        return None
    try:
        loop = asyncio.get_event_loop()
        infos = await loop.run_in_executor(None, socket.getaddrinfo, host, None)
        ip = infos[0][4][0]
    except Exception:
        return None

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(
                IPINFO_URL.format(ip=ip),
                headers={"User-Agent": "ThreatLens-Scanner/1.0 (Authorized Security Audit)"},
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            org = data.get("org", "")
            if not org:
                return None
            return {"ip": ip, "org": org, "country": data.get("country", "")}
    except Exception:
        return None
