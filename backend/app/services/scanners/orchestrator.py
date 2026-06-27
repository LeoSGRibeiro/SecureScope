"""
Scan Orchestrator
Runs all scanner modules for a given target and aggregates results.
"""
import asyncio
import time
from app.services.scanners import (
    headers_scanner,
    tls_scanner,
    cookies_scanner,
    cors_scanner,
    fingerprint_scanner,
    subdomains_scanner,
    owasp_scanner,
    port_scanner,
)
from app.services.scanners.base import ScanResult, Finding, calculate_risk_score

MODULE_MAP = {
    "headers": headers_scanner.scan,
    "tls": tls_scanner.scan,
    "cookies": cookies_scanner.scan,
    "cors": cors_scanner.scan,
    "fingerprint": fingerprint_scanner.scan,
    "subdomains": subdomains_scanner.scan,
    "owasp": owasp_scanner.scan,
    "port_scan": port_scanner.scan,
}

FULL_SCAN_MODULES = list(MODULE_MAP.keys())


async def run_scan(url: str, modules: list[str] | None = None) -> dict:
    if modules is None or not modules:
        modules = FULL_SCAN_MODULES

    start = time.monotonic()
    tasks = {
        name: asyncio.create_task(MODULE_MAP[name](url))
        for name in modules
        if name in MODULE_MAP
    }

    module_results: dict[str, ScanResult] = {}
    for name, task in tasks.items():
        try:
            result = await task
        except Exception as e:
            result = ScanResult(module=name, error=str(e))
        module_results[name] = result

    all_findings: list[Finding] = []
    for r in module_results.values():
        all_findings.extend(r.findings)

    risk_score = calculate_risk_score(all_findings)
    duration_ms = int((time.monotonic() - start) * 1000)

    return {
        "url": url,
        "modules_run": list(module_results.keys()),
        "duration_ms": duration_ms,
        "risk_score": risk_score,
        "findings": [_finding_to_dict(f) for f in all_findings],
        "module_results": {
            name: {
                "error": r.error,
                "duration_ms": r.duration_ms,
                "findings_count": len(r.findings),
                "raw_data": r.raw_data,
            }
            for name, r in module_results.items()
        },
    }


def _finding_to_dict(f: Finding) -> dict:
    return {
        "title": f.title,
        "description": f.description,
        "severity": f.severity.value,
        "category": f.category,
        "module": f.module,
        "affected_url": f.affected_url,
        "evidence": f.evidence,
        "recommendation": f.recommendation,
        "references": f.references,
        "owasp_category": f.owasp_category,
        "cvss_score": f.cvss_score,
        "cve": f.cve,
    }
