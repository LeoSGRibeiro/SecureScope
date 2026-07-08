"""
Outdated-version detection: compares a version string extracted from HTTP
headers/HTML (by fingerprint_scanner.py) against the latest stable release
of that product, sourced from the free, unauthenticated endoflife.date API.
Best-effort only, same philosophy as cve_lookup.py: any failure (timeout,
unknown product, unparsable version) is swallowed and simply yields no
finding — a lookup outage must never break a scan.
"""
import httpx
from packaging import version
from packaging.version import InvalidVersion
from app.services.scanners.base import Finding, Severity

EOL_API_URL = "https://endoflife.date/api/{product}.json"

# IIS is deliberately excluded: there is no public "latest IIS version"
# decoupled from Windows Server releases, so it stays detection-only.
PRODUCT_SLUGS = {
    "PHP": "php",
    "Nginx": "nginx",
    "Apache": "apache",
    "WordPress": "wordpress",
    "Apache Tomcat": "tomcat",
}


async def get_latest_version(slug: str, timeout: float = 10.0) -> str | None:
    """Returns the newest 'latest' version string from endoflife.date, or
    None on any failure (timeout, non-200, redirect-then-fail, malformed
    JSON, empty array)."""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(
                EOL_API_URL.format(product=slug),
                headers={"User-Agent": "ThreatLens-Scanner/1.0 (Authorized Security Audit)"},
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            if not data:
                return None
            return data[0].get("latest")
    except Exception:
        return None


def _severity_for_gap(current: version.Version, latest: version.Version) -> Severity:
    if current.major < latest.major:
        return Severity.high
    if current.minor < latest.minor:
        return Severity.medium
    return Severity.low


async def get_comparison(tech: str, current_version_str: str) -> dict | None:
    """Single source of truth for a tech's version-vs-latest comparison, used
    both for the granular 'Outdated X' Finding and for the consolidated
    recommendation text in the Infrastructure & Technology Profile finding —
    avoids querying endoflife.date twice for the same technology.
    Returns None when the tech isn't tracked or the version doesn't parse.
    Returns {"tracked": True, "latest": None, ...} when the lookup itself
    fails (so callers can still say "tracked but lookup unavailable" rather
    than silently treating it the same as an untracked technology).
    """
    slug = PRODUCT_SLUGS.get(tech)
    if not slug:
        return None

    try:
        current = version.parse(current_version_str)
    except InvalidVersion:
        return None

    latest_str = await get_latest_version(slug)
    if not latest_str:
        return {"tracked": True, "current": current_version_str, "latest": None, "outdated": False, "severity": None}

    try:
        latest = version.parse(latest_str)
    except InvalidVersion:
        return {"tracked": True, "current": current_version_str, "latest": None, "outdated": False, "severity": None}

    outdated = current < latest
    return {
        "tracked": True,
        "current": current_version_str,
        "latest": latest_str,
        "outdated": outdated,
        "severity": _severity_for_gap(current, latest) if outdated else None,
    }


async def build_version_findings(tech: str, current_version_str: str, url: str) -> list[Finding]:
    """Never raises. Returns [] when the tech isn't tracked, the version
    string doesn't parse, the lookup fails, or the version is already current."""
    comparison = await get_comparison(tech, current_version_str)
    if not comparison or not comparison["outdated"]:
        return []

    latest_str = comparison["latest"]
    return [Finding(
        title=f"Outdated {tech} Version Detected: {current_version_str} (Latest: {latest_str})",
        description=(
            f"The target is running {tech} version {current_version_str}. "
            f"The latest stable {tech} release is {latest_str}."
        ),
        severity=comparison["severity"],
        category="Fingerprint",
        module="fingerprint",
        affected_url=url,
        evidence={"technology": tech, "detected_version": current_version_str, "latest_version": latest_str},
        recommendation=f"Upgrade {tech} from {current_version_str} to {latest_str} or the latest stable release in that line.",
        owasp_category="A06:2021 – Vulnerable and Outdated Components",
    )]
