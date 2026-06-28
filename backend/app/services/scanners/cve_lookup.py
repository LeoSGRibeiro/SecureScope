"""
Live CVE lookup against the official CVE List (https://www.cve.org/).
cve.org itself does not expose a public, unauthenticated keyword-search API,
so this queries the NVD (National Vulnerability Database) REST API, which
ingests and enriches the exact same CVE List published by the CVE Program —
each result still links back to the canonical record at cve.org/CVERecord.

Best-effort only: NVD is unauthenticated-rate-limited (~5 req/30s), so any
failure (timeout, rate limit, no match) is swallowed and simply yields no
CVE — a lookup outage must never break a scan.
"""
import httpx
from app.services.scanners.base import Severity

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ORG_RECORD_URL = "https://www.cve.org/CVERecord?id={cve_id}"


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.critical
    if score >= 7.0:
        return Severity.high
    if score >= 4.0:
        return Severity.medium
    if score > 0:
        return Severity.low
    return Severity.informational


async def search_cves(keyword: str, max_results: int = 3, timeout: float = 25.0, fetch_size: int = 20) -> list[dict]:
    """Query the CVE List (via NVD) by keyword, e.g. "jquery". NVD's keyword
    search matches substrings of the CVE description, so multi-word phrases
    that include an exact version number rarely match — search by product
    name only, fetch a larger batch, and rank client-side by CVSS severity
    (NVD's API has no native sort-by-score parameter).
    Returns up to max_results dicts: id, description, cvss_score, severity, url."""
    results: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                NVD_API_URL,
                params={"keywordSearch": keyword, "resultsPerPage": fetch_size},
                headers={"User-Agent": "ThreatLens-Scanner/1.0 (Authorized Security Audit)"},
            )
            if resp.status_code != 200:
                return results
            data = resp.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue
                descriptions = cve.get("descriptions", [])
                description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")

                score = 0.0
                metrics = cve.get("metrics", {})
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(metric_key)
                    if metric_list:
                        score = metric_list[0].get("cvssData", {}).get("baseScore", 0.0)
                        break

                results.append({
                    "id": cve_id,
                    "description": description[:300],
                    "cvss_score": score,
                    "severity": _cvss_to_severity(score),
                    "url": CVE_ORG_RECORD_URL.format(cve_id=cve_id),
                })
    except Exception:
        pass
    results.sort(key=lambda r: r["cvss_score"], reverse=True)
    return results[:max_results]
