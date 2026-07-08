"""
Controlled Login Brute-Force Scanner (INTRUSIVE)
Tests a small, fixed list of common/default credential pairs against a
detected login form. Sequential (not concurrent) with a deliberate delay
between attempts to minimize the risk of triggering account lockouts or
rate-limit bans on the target, and stops immediately on the first
apparent success. If no login form is found, no requests are sent.
"""
import asyncio
import time
import httpx
from bs4 import BeautifulSoup
from app.services.scanners.base import Finding, ScanResult, Severity

CREDENTIAL_PAIRS = [
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "P@ssw0rd"),
    ("root", "root"),
    ("administrator", "administrator"),
    ("test", "test"),
    ("user", "user"),
    ("admin", ""),
    ("guest", "guest"),
    ("admin", "changeme"),
]

THROTTLE_SECONDS = 2.0
REQUEST_TIMEOUT = 15


def _find_login_form(body: str) -> dict | None:
    soup = BeautifulSoup(body, "lxml")
    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        has_password = any(i.get("type", "").lower() == "password" for i in inputs)
        text_field = next(
            (i.get("name") for i in inputs if i.get("type", "").lower() in ("text", "email", "") and i.get("name")),
            None,
        )
        password_field = next((i.get("name") for i in inputs if i.get("type", "").lower() == "password"), None)
        if has_password and text_field and password_field:
            return {
                "action": form.get("action") or "",
                "method": (form.get("method") or "post").lower(),
                "user_field": text_field,
                "pass_field": password_field,
            }
    return None


async def scan(url: str, timeout: int = 60) -> ScanResult:
    start = time.monotonic()
    findings: list[Finding] = []
    raw: dict = {"attempts": 0}

    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": "ThreatLens-Scanner/1.0 (Authorized Security Audit)"},
        ) as client:
            baseline = await client.get(url, timeout=REQUEST_TIMEOUT)
            form = _find_login_form(baseline.text)

            if not form:
                findings.append(Finding(
                    title="No Login Form Detected",
                    description="No HTML form with a password field was found on the target page; no credential attempts were made.",
                    severity=Severity.informational,
                    category="Authentication",
                    module="auth_bruteforce",
                    affected_url=url,
                ))
                duration = int((time.monotonic() - start) * 1000)
                return ScanResult(module="auth_bruteforce", findings=findings, raw_data=raw, duration_ms=duration)

            action_url = form["action"] or url
            if not action_url.startswith("http"):
                action_url = httpx.URL(url).join(action_url).human_repr()

            baseline_has_password_field = 'type="password"' in baseline.text or "type='password'" in baseline.text
            baseline_cookies = set(baseline.cookies.keys())

            for username, password in CREDENTIAL_PAIRS:
                raw["attempts"] += 1
                try:
                    data = {form["user_field"]: username, form["pass_field"]: password}
                    resp = await client.post(action_url, data=data, timeout=REQUEST_TIMEOUT)

                    is_redirect = resp.status_code in (301, 302, 303, 307, 308)
                    redirected_elsewhere = is_redirect and resp.headers.get("location", "") not in ("", url, action_url)
                    password_field_gone = (
                        'type="password"' in resp.text or "type='password'" in resp.text
                    ) is False and baseline_has_password_field
                    new_session_cookie = bool(set(resp.cookies.keys()) - baseline_cookies)

                    if redirected_elsewhere or password_field_gone or new_session_cookie:
                        findings.append(Finding(
                            title="Weak/Default Credentials Accepted",
                            description=f"The login form accepted a common/default credential pair (username '{username}').",
                            severity=Severity.critical,
                            category="Authentication",
                            module="auth_bruteforce",
                            affected_url=action_url,
                            evidence={"username": username, "password": "***redacted***"},
                            recommendation="Enforce a strong password policy, multi-factor authentication, and account lockout after repeated failures.",
                            owasp_category="A07:2021 – Identification and Authentication Failures",
                        ))
                        break
                except Exception:
                    pass

                await asyncio.sleep(THROTTLE_SECONDS)

            if not findings:
                findings.append(Finding(
                    title="No Default/Weak Credentials Accepted",
                    description=f"None of the {len(CREDENTIAL_PAIRS)} tested common credential pairs were accepted by the login form.",
                    severity=Severity.informational,
                    category="Authentication",
                    module="auth_bruteforce",
                    affected_url=action_url,
                ))

    except httpx.RequestError as e:
        return ScanResult(module="auth_bruteforce", error=str(e))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="auth_bruteforce", findings=findings, raw_data=raw, duration_ms=duration)
