"""
HTTP Security Headers Scanner
Analyzes response headers for security misconfigurations (defensive, read-only).
"""
import time
import httpx
from app.services.scanners.base import Finding, ScanResult, Severity

REQUIRED_HEADERS = {
    "strict-transport-security": {
        "title": "Missing HSTS Header",
        "severity": Severity.high,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
    },
    "content-security-policy": {
        "title": "Missing Content-Security-Policy Header",
        "severity": Severity.high,
        "owasp": "A03:2021 – Injection",
        "recommendation": "Define a strict CSP policy to mitigate XSS and data injection attacks.",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"],
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options Header",
        "severity": Severity.medium,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options Header",
        "severity": Severity.low,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Add 'X-Content-Type-Options: nosniff'",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy Header",
        "severity": Severity.low,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
    },
    "permissions-policy": {
        "title": "Missing Permissions-Policy Header",
        "severity": Severity.informational,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Add Permissions-Policy to restrict browser feature access.",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
    },
}

INSECURE_HEADERS = {
    "server": {
        "title": "Server Version Disclosure via 'Server' Header",
        "severity": Severity.low,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Remove or anonymize the Server header to prevent technology fingerprinting.",
    },
    "x-powered-by": {
        "title": "Technology Disclosure via 'X-Powered-By' Header",
        "severity": Severity.low,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Remove the X-Powered-By header.",
    },
    "x-aspnet-version": {
        "title": "ASP.NET Version Disclosed",
        "severity": Severity.medium,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Disable version disclosure in ASP.NET configuration.",
    },
}


async def scan(url: str, timeout: int = 15) -> ScanResult:
    start = time.monotonic()
    findings: list[Finding] = []
    raw: dict = {}

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "SecureScope-Scanner/1.0 (Authorized Security Audit)"},
        ) as client:
            response = await client.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            raw["status_code"] = response.status_code
            raw["headers"] = dict(response.headers)
            raw["final_url"] = str(response.url)

        # Check for missing security headers
        for header_name, meta in REQUIRED_HEADERS.items():
            if header_name not in headers:
                findings.append(Finding(
                    title=meta["title"],
                    description=f"The header '{header_name}' is absent from the HTTP response.",
                    severity=meta["severity"],
                    category="HTTP Security Headers",
                    module="headers",
                    affected_url=url,
                    evidence={"missing_header": header_name, "response_headers": dict(raw["headers"])},
                    recommendation=meta["recommendation"],
                    references=meta["refs"],
                    owasp_category=meta["owasp"],
                ))

        # Validate HSTS if present
        hsts_val = headers.get("strict-transport-security", "")
        if hsts_val:
            if "max-age" not in hsts_val:
                findings.append(Finding(
                    title="HSTS Header Missing max-age",
                    description="HSTS header is present but lacks max-age directive.",
                    severity=Severity.medium,
                    category="HTTP Security Headers",
                    module="headers",
                    affected_url=url,
                    evidence={"header_value": hsts_val},
                    recommendation="Include 'max-age=31536000' in HSTS header.",
                    owasp_category="A05:2021 – Security Misconfiguration",
                ))
            try:
                max_age = int([p for p in hsts_val.split(";") if "max-age" in p][0].split("=")[1].strip())
                if max_age < 15768000:
                    findings.append(Finding(
                        title="HSTS max-age Too Short",
                        description=f"HSTS max-age is {max_age}s (< 6 months). Recommend ≥ 31536000s.",
                        severity=Severity.low,
                        category="HTTP Security Headers",
                        module="headers",
                        affected_url=url,
                        evidence={"max_age": max_age},
                        recommendation="Set max-age to at least 31536000 (1 year).",
                    ))
            except Exception:
                pass

        # Check for CSP weaknesses
        csp = headers.get("content-security-policy", "")
        if csp:
            if "unsafe-inline" in csp:
                findings.append(Finding(
                    title="CSP Allows 'unsafe-inline'",
                    description="Content-Security-Policy contains 'unsafe-inline', weakening XSS protection.",
                    severity=Severity.medium,
                    category="HTTP Security Headers",
                    module="headers",
                    affected_url=url,
                    evidence={"csp": csp},
                    recommendation="Remove 'unsafe-inline' and use nonces or hashes instead.",
                    owasp_category="A03:2021 – Injection",
                ))
            if "unsafe-eval" in csp:
                findings.append(Finding(
                    title="CSP Allows 'unsafe-eval'",
                    description="Content-Security-Policy contains 'unsafe-eval', enabling script injection.",
                    severity=Severity.medium,
                    category="HTTP Security Headers",
                    module="headers",
                    affected_url=url,
                    evidence={"csp": csp},
                    recommendation="Remove 'unsafe-eval' from CSP.",
                    owasp_category="A03:2021 – Injection",
                ))
            if "* " in csp or csp.strip().endswith("*"):
                findings.append(Finding(
                    title="CSP Contains Wildcard Source",
                    description="CSP policy uses wildcard '*' which undermines protection.",
                    severity=Severity.medium,
                    category="HTTP Security Headers",
                    module="headers",
                    affected_url=url,
                    evidence={"csp": csp},
                    recommendation="Replace wildcard sources with specific, trusted origins.",
                ))

        # Check for information-leaking headers
        for h, meta in INSECURE_HEADERS.items():
            if h in headers:
                findings.append(Finding(
                    title=meta["title"],
                    description=f"Header '{h}: {headers[h]}' reveals technology details.",
                    severity=meta["severity"],
                    category="Information Disclosure",
                    module="headers",
                    affected_url=url,
                    evidence={"header": h, "value": headers[h]},
                    recommendation=meta["recommendation"],
                    owasp_category=meta["owasp"],
                ))

        # Check for cache-control on sensitive responses
        cache = headers.get("cache-control", "")
        if not cache or ("no-store" not in cache and "private" not in cache):
            findings.append(Finding(
                title="Potentially Cacheable Response",
                description="Cache-Control header does not prevent caching of potentially sensitive content.",
                severity=Severity.informational,
                category="HTTP Security Headers",
                module="headers",
                affected_url=url,
                evidence={"cache_control": cache or "(not set)"},
                recommendation="Add 'Cache-Control: no-store, private' for sensitive pages.",
            ))

    except httpx.TimeoutException:
        return ScanResult(module="headers", error=f"Request timed out after {timeout}s")
    except httpx.RequestError as e:
        return ScanResult(module="headers", error=str(e))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="headers", findings=findings, raw_data=raw, duration_ms=duration)
