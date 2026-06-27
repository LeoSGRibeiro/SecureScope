"""
Cookie Security Scanner
Analyzes Set-Cookie headers for missing security attributes (read-only).
"""
import time
import httpx
from app.services.scanners.base import Finding, ScanResult, Severity


async def scan(url: str, timeout: int = 15) -> ScanResult:
    start = time.monotonic()
    findings: list[Finding] = []
    raw: dict = {"cookies": []}

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "SecureScope-Scanner/1.0 (Authorized Security Audit)"},
        ) as client:
            response = await client.get(url)

        all_set_cookie = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
        if not all_set_cookie:
            # httpx merges duplicate headers; iterate raw
            all_set_cookie = [v for k, v in response.headers.items() if k.lower() == "set-cookie"]

        raw["status_code"] = response.status_code

        if not all_set_cookie:
            findings.append(Finding(
                title="No Cookies Detected",
                description="No Set-Cookie headers found in the response. If the application uses sessions, verify that cookies are being set.",
                severity=Severity.informational,
                category="Cookies",
                module="cookies",
                affected_url=url,
            ))
            duration = int((time.monotonic() - start) * 1000)
            return ScanResult(module="cookies", findings=findings, raw_data=raw, duration_ms=duration)

        for cookie_str in all_set_cookie:
            parts = [p.strip() for p in cookie_str.split(";")]
            name_value = parts[0]
            name = name_value.split("=")[0].strip() if "=" in name_value else name_value
            attrs_lower = [p.lower() for p in parts[1:]]
            raw["cookies"].append({"name": name, "raw": cookie_str})

            is_https = url.startswith("https://")

            if "httponly" not in attrs_lower:
                findings.append(Finding(
                    title=f"Cookie '{name}' Missing HttpOnly Flag",
                    description=f"Cookie '{name}' is accessible via JavaScript (no HttpOnly). This enables XSS-based session hijacking.",
                    severity=Severity.medium,
                    category="Cookies",
                    module="cookies",
                    affected_url=url,
                    evidence={"cookie_name": name, "raw_header": cookie_str},
                    recommendation=f"Add 'HttpOnly' attribute to cookie '{name}'.",
                    owasp_category="A02:2021 – Cryptographic Failures",
                    references=["https://owasp.org/www-community/HttpOnly"],
                ))

            if is_https and "secure" not in attrs_lower:
                findings.append(Finding(
                    title=f"Cookie '{name}' Missing Secure Flag",
                    description=f"Cookie '{name}' may be transmitted over unencrypted HTTP connections.",
                    severity=Severity.medium,
                    category="Cookies",
                    module="cookies",
                    affected_url=url,
                    evidence={"cookie_name": name, "raw_header": cookie_str},
                    recommendation=f"Add 'Secure' attribute to cookie '{name}'.",
                    owasp_category="A02:2021 – Cryptographic Failures",
                ))

            samesite_attrs = [p for p in attrs_lower if "samesite" in p]
            if not samesite_attrs:
                findings.append(Finding(
                    title=f"Cookie '{name}' Missing SameSite Attribute",
                    description=f"Cookie '{name}' has no SameSite attribute, leaving it vulnerable to CSRF attacks.",
                    severity=Severity.medium,
                    category="Cookies",
                    module="cookies",
                    affected_url=url,
                    evidence={"cookie_name": name, "raw_header": cookie_str},
                    recommendation=f"Add 'SameSite=Strict' or 'SameSite=Lax' to cookie '{name}'.",
                    owasp_category="A01:2021 – Broken Access Control",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
                ))
            else:
                samesite_val = samesite_attrs[0].split("=")[-1].strip() if "=" in samesite_attrs[0] else ""
                if samesite_val == "none" and "secure" not in attrs_lower:
                    findings.append(Finding(
                        title=f"Cookie '{name}' SameSite=None Without Secure",
                        description="SameSite=None requires the Secure attribute; otherwise modern browsers will reject it.",
                        severity=Severity.medium,
                        category="Cookies",
                        module="cookies",
                        affected_url=url,
                        evidence={"cookie_name": name, "raw_header": cookie_str},
                        recommendation="Add Secure attribute when using SameSite=None.",
                    ))

            # Session cookies without expiry — informational
            has_expiry = any("expires=" in p or "max-age=" in p for p in attrs_lower)
            if not has_expiry and ("session" in name.lower() or "auth" in name.lower() or "token" in name.lower()):
                findings.append(Finding(
                    title=f"Session Cookie '{name}' Has No Expiry",
                    description="Session cookie lacks an expiry date; it persists until the browser is closed.",
                    severity=Severity.informational,
                    category="Cookies",
                    module="cookies",
                    affected_url=url,
                    evidence={"cookie_name": name},
                    recommendation="Set an explicit Max-Age or Expires for session cookies.",
                ))

    except httpx.TimeoutException:
        return ScanResult(module="cookies", error=f"Request timed out after {timeout}s")
    except httpx.RequestError as e:
        return ScanResult(module="cookies", error=str(e))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="cookies", findings=findings, raw_data=raw, duration_ms=duration)
