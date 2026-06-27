"""
OWASP Top 10 Passive/Defensive Scanner
Identifies indicators of OWASP Top 10 issues without active exploitation.
All checks are read-only and non-destructive.
"""
import re
import time
import httpx
from bs4 import BeautifulSoup
from app.services.scanners.base import Finding, ScanResult, Severity

# Error patterns suggesting verbose error disclosure
ERROR_PATTERNS = [
    (r"SQL syntax.*MySQL", "MySQL SQL Error Disclosed", Severity.high, "A03:2021 – Injection"),
    (r"Warning:.*mysql_", "MySQL PHP Warning Exposed", Severity.high, "A03:2021 – Injection"),
    (r"ORA-[0-9]{5}", "Oracle Database Error Disclosed", Severity.high, "A03:2021 – Injection"),
    (r"Microsoft OLE DB.*SQL Server", "MSSQL OLE DB Error Disclosed", Severity.high, "A03:2021 – Injection"),
    (r"SQLSTATE\[", "SQL State Error Disclosed", Severity.high, "A03:2021 – Injection"),
    (r"Traceback \(most recent call last\)", "Python Stack Trace Disclosed", Severity.medium, "A05:2021 – Security Misconfiguration"),
    (r"at .+\(.*\.java:\d+\)", "Java Stack Trace Disclosed", Severity.medium, "A05:2021 – Security Misconfiguration"),
    (r"Exception in thread", "Java Exception Disclosed", Severity.medium, "A05:2021 – Security Misconfiguration"),
    (r"Parse error:.*in .*on line", "PHP Parse Error Disclosed", Severity.medium, "A05:2021 – Security Misconfiguration"),
    (r"Notice:.*Undefined variable", "PHP Notice Disclosed", Severity.low, "A05:2021 – Security Misconfiguration"),
    (r"Fatal error:.*in .*on line", "PHP Fatal Error Disclosed", Severity.high, "A05:2021 – Security Misconfiguration"),
    (r"\bpassword\b.*=.*\S+", "Possible Credential in Response Body", Severity.critical, "A02:2021 – Cryptographic Failures"),
    (r"api[_-]?key.*[:=].*[A-Za-z0-9]{16,}", "API Key Exposed in Response", Severity.critical, "A02:2021 – Cryptographic Failures"),
    (r"Authorization: Bearer [A-Za-z0-9\-_\.]+", "Bearer Token in Response Body", Severity.critical, "A02:2021 – Cryptographic Failures"),
]

# Patterns for reflected content in response that may indicate XSS reflection points
XSS_INDICATORS = [
    r"<script>alert\(",
    r"javascript:void",
    r"onerror=",
    r"onload=",
]

SENSITIVE_FILE_PATHS = [
    ("/.git/HEAD", "Git Repository Exposed"),
    ("/.env", ".env File Exposed"),
    ("/config.php", "PHP Config File Exposed"),
    ("/wp-config.php", "WordPress Config Exposed"),
    ("/configuration.php", "Joomla Config Exposed"),
    ("/settings.py", "Django Settings Exposed"),
    ("/web.config", "ASP.NET web.config Exposed"),
    ("/composer.json", "PHP Composer Manifest Exposed"),
    ("/package.json", "Node.js Package Manifest Exposed"),
    ("/Dockerfile", "Dockerfile Exposed"),
    ("/docker-compose.yml", "Docker Compose Exposed"),
    ("/backup.sql", "SQL Backup File Exposed"),
    ("/dump.sql", "SQL Dump Exposed"),
    ("/robots.txt", "robots.txt (informational)"),
    ("/sitemap.xml", "sitemap.xml (informational)"),
]


async def scan(url: str, timeout: int = 15) -> ScanResult:
    start = time.monotonic()
    findings: list[Finding] = []
    raw: dict = {"exposed_files": [], "error_patterns": []}

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "ThreatLens-Scanner/1.0 (Authorized Security Audit)"},
        ) as client:
            response = await client.get(url)
            body = response.text
            headers = {k.lower(): v for k, v in response.headers.items()}
            raw["status_code"] = response.status_code

            # Error pattern analysis
            for pattern, title, sev, owasp in ERROR_PATTERNS:
                m = re.search(pattern, body, re.IGNORECASE)
                if m:
                    snippet = m.group(0)[:200]
                    raw["error_patterns"].append(title)
                    findings.append(Finding(
                        title=title,
                        description=f"Response body contains a pattern suggesting information leakage: '{snippet[:80]}...'",
                        severity=sev,
                        category="Information Disclosure",
                        module="owasp",
                        affected_url=url,
                        evidence={"pattern": pattern, "snippet": snippet},
                        recommendation="Suppress verbose error messages in production. Use generic error pages.",
                        owasp_category=owasp,
                    ))

            # Check for XSS reflection indicators (informational only — no injection attempted)
            for xss_pat in XSS_INDICATORS:
                if re.search(xss_pat, body, re.IGNORECASE):
                    findings.append(Finding(
                        title="Possible Reflected XSS Indicator in Response",
                        description="Response body contains patterns associated with cross-site scripting payloads. Manual verification required.",
                        severity=Severity.medium,
                        category="XSS Indicators",
                        module="owasp",
                        affected_url=url,
                        evidence={"pattern": xss_pat},
                        recommendation="Review output encoding and implement a strict CSP. No active testing was performed.",
                        owasp_category="A03:2021 – Injection",
                    ))

            # Directory listing detection
            if "Index of /" in body or "Directory listing" in body.lower():
                findings.append(Finding(
                    title="Directory Listing Enabled",
                    description="The web server is exposing a directory listing, which reveals file structure.",
                    severity=Severity.medium,
                    category="Information Disclosure",
                    module="owasp",
                    affected_url=url,
                    evidence={"indicator": "Directory listing detected in response body"},
                    recommendation="Disable directory listing in the web server configuration.",
                    owasp_category="A05:2021 – Security Misconfiguration",
                ))

            # Check for mixed content (HTTPS page loading HTTP resources)
            if url.startswith("https://"):
                soup = BeautifulSoup(body, "lxml")
                http_resources = []
                for tag in soup.find_all(["script", "link", "img", "iframe"]):
                    src = tag.get("src") or tag.get("href") or ""
                    if src.startswith("http://"):
                        http_resources.append(src[:100])
                if http_resources:
                    findings.append(Finding(
                        title="Mixed Content Detected",
                        description=f"HTTPS page loads {len(http_resources)} resource(s) over HTTP.",
                        severity=Severity.medium,
                        category="Mixed Content",
                        module="owasp",
                        affected_url=url,
                        evidence={"http_resources": http_resources[:10]},
                        recommendation="Serve all resources over HTTPS.",
                        owasp_category="A02:2021 – Cryptographic Failures",
                    ))

            # Check for inline event handlers (potential XSS surface)
            soup = BeautifulSoup(body, "lxml")
            inline_events = soup.find_all(attrs=re.compile(r"^on\w+"))
            if len(inline_events) > 5:
                findings.append(Finding(
                    title=f"High Number of Inline Event Handlers ({len(inline_events)})",
                    description="Large number of inline JavaScript event handlers detected. These can bypass CSP.",
                    severity=Severity.low,
                    category="XSS Indicators",
                    module="owasp",
                    affected_url=url,
                    evidence={"count": len(inline_events)},
                    recommendation="Move event handlers to external scripts and use a strict CSP.",
                ))

            # Hidden form inputs (potential CSRF token presence check)
            forms = soup.find_all("form")
            for form in forms:
                hidden_inputs = form.find_all("input", attrs={"type": "hidden"})
                token_found = any(
                    "csrf" in (inp.get("name", "") + inp.get("id", "")).lower()
                    or "token" in (inp.get("name", "") + inp.get("id", "")).lower()
                    for inp in hidden_inputs
                )
                action = form.get("action", url)
                method = form.get("method", "get").upper()
                if method == "POST" and not token_found:
                    findings.append(Finding(
                        title="POST Form Without Apparent CSRF Token",
                        description=f"A POST form (action: {action}) has no detectable CSRF token field.",
                        severity=Severity.medium,
                        category="CSRF",
                        module="owasp",
                        affected_url=url,
                        evidence={"form_action": action, "method": method},
                        recommendation="Add CSRF token to all state-changing POST forms.",
                        owasp_category="A01:2021 – Broken Access Control",
                    ))

            # Probe sensitive files
            base = url.rstrip("/")
            for path, desc in SENSITIVE_FILE_PATHS:
                try:
                    probe = await client.get(f"{base}{path}", follow_redirects=False)
                    if probe.status_code == 200:
                        content_snippet = probe.text[:300] if probe.text else ""
                        sev = Severity.informational if path in ("/robots.txt", "/sitemap.xml") else Severity.high
                        raw["exposed_files"].append({"path": path, "status": 200})
                        findings.append(Finding(
                            title=f"{desc} — HTTP 200",
                            description=f"File '{path}' is publicly accessible and may expose sensitive information.",
                            severity=sev,
                            category="Information Disclosure",
                            module="owasp",
                            affected_url=f"{base}{path}",
                            evidence={"path": path, "snippet": content_snippet[:200]},
                            recommendation=f"Restrict access to '{path}'. Remove from public web root if not needed.",
                            owasp_category="A05:2021 – Security Misconfiguration",
                        ))
                except Exception:
                    pass

    except httpx.TimeoutException:
        return ScanResult(module="owasp", error=f"Request timed out after {timeout}s")
    except httpx.RequestError as e:
        return ScanResult(module="owasp", error=str(e))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="owasp", findings=findings, raw_data=raw, duration_ms=duration)
