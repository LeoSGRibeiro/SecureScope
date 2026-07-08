"""
Active SQLi/XSS Injection Scanner (INTRUSIVE)
Sends real test payloads to query parameters and form fields to confirm
injection vulnerabilities, rather than only detecting passive indicators
(see owasp_scanner.py for the passive-only checks). Non-destructive:
payloads are read-only probes (no data-modifying statements), but they
do generate attack-like traffic and may trip a WAF/IDS on the target.
"""
import asyncio
import time
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx
from bs4 import BeautifulSoup
from app.services.scanners.base import Finding, ScanResult, Severity
from app.services.scanners.owasp_scanner import ERROR_PATTERNS
import re

SQLI_PAYLOADS = ["'", "' OR '1'='1", "' OR 1=1--", '"', "1' AND '1'='2"]
SQLI_TIME_PAYLOAD = "';WAITFOR DELAY '0:0:3'--"
TIME_BASELINE_THRESHOLD = 2.0  # only try the time-based payload if baseline is fast
TIME_DELAY_THRESHOLD = 2.5  # response must take at least this long to count as a hit

MAX_CONCURRENCY = 5
REQUEST_TIMEOUT = 10


def _build_url(base_url: str, params: dict) -> str:
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _discover_params(url: str, body: str) -> list[str]:
    params = list(parse_qs(urlparse(url).query).keys())
    soup = BeautifulSoup(body, "lxml")
    for form in soup.find_all("form"):
        for inp in form.find_all(["input", "textarea"]):
            name = inp.get("name")
            if name and name not in params:
                params.append(name)
    return params


async def _check_sqli(client: httpx.AsyncClient, url: str, param: str, baseline_len: int, semaphore: asyncio.Semaphore) -> Finding | None:
    async with semaphore:
        try:
            base_qs = parse_qs(urlparse(url).query)
            for payload in SQLI_PAYLOADS:
                qs = {**base_qs, param: payload}
                test_url = _build_url(url, qs)
                resp = await client.get(test_url, timeout=REQUEST_TIMEOUT)
                for pattern, title, sev, owasp in ERROR_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        return Finding(
                            title=f"Possible SQL Injection — Parameter '{param}'",
                            description=f"Payload {payload!r} on parameter '{param}' triggered a database/application error pattern ({title}).",
                            severity=Severity.critical,
                            category="Injection",
                            module="sqli_xss",
                            affected_url=test_url,
                            evidence={"param": param, "payload": payload, "matched_pattern": pattern},
                            recommendation="Use parameterized queries/prepared statements; validate and escape all user input.",
                            owasp_category="A03:2021 – Injection",
                        )
                if abs(len(resp.text) - baseline_len) > baseline_len * 0.3 and baseline_len > 0:
                    return Finding(
                        title=f"Possible SQL Injection — Parameter '{param}'",
                        description=f"Payload {payload!r} on parameter '{param}' caused a significant response size change compared to baseline.",
                        severity=Severity.high,
                        category="Injection",
                        module="sqli_xss",
                        affected_url=test_url,
                        evidence={"param": param, "payload": payload, "baseline_len": baseline_len, "response_len": len(resp.text)},
                        recommendation="Use parameterized queries/prepared statements; validate and escape all user input.",
                        owasp_category="A03:2021 – Injection",
                    )

            # Time-based blind SQLi — only if baseline latency is fast (avoid false positives on slow sites)
            base_start = time.monotonic()
            await client.get(url, timeout=REQUEST_TIMEOUT)
            baseline_latency = time.monotonic() - base_start
            if baseline_latency < TIME_BASELINE_THRESHOLD:
                qs = {**base_qs, param: SQLI_TIME_PAYLOAD}
                test_url = _build_url(url, qs)
                start = time.monotonic()
                await client.get(test_url, timeout=REQUEST_TIMEOUT)
                elapsed = time.monotonic() - start
                if elapsed >= TIME_DELAY_THRESHOLD:
                    return Finding(
                        title=f"Possible Time-Based Blind SQL Injection — Parameter '{param}'",
                        description=f"Injecting a time-delay payload into parameter '{param}' caused the response to take {elapsed:.1f}s (baseline {baseline_latency:.1f}s).",
                        severity=Severity.critical,
                        category="Injection",
                        module="sqli_xss",
                        affected_url=test_url,
                        evidence={"param": param, "payload": SQLI_TIME_PAYLOAD, "elapsed": elapsed, "baseline": baseline_latency},
                        recommendation="Use parameterized queries/prepared statements; validate and escape all user input.",
                        owasp_category="A03:2021 – Injection",
                    )
        except Exception:
            pass
    return None


async def _check_xss(client: httpx.AsyncClient, url: str, param: str, semaphore: asyncio.Semaphore) -> Finding | None:
    async with semaphore:
        try:
            base_qs = parse_qs(urlparse(url).query)
            marker = f"ssxss{uuid.uuid4().hex[:8]}"
            payload = f'"><svg id={marker}>'
            qs = {**base_qs, param: payload}
            test_url = _build_url(url, qs)
            resp = await client.get(test_url, timeout=REQUEST_TIMEOUT)
            if f"<svg id={marker}>" in resp.text:
                return Finding(
                    title=f"Reflected XSS — Parameter '{param}' Not Sanitized",
                    description=f"Parameter '{param}' reflects an injected payload unescaped in the response body, indicating a reflected XSS vulnerability.",
                    severity=Severity.high,
                    category="Injection",
                    module="sqli_xss",
                    affected_url=test_url,
                    evidence={"param": param, "marker": marker},
                    recommendation="HTML-encode all output; implement a strict Content-Security-Policy.",
                    owasp_category="A03:2021 – Injection",
                )
        except Exception:
            pass
    return None


async def scan(url: str, timeout: int = 30) -> ScanResult:
    start = time.monotonic()
    findings: list[Finding] = []
    raw: dict = {"params_tested": []}

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "ThreatLens-Scanner/1.0 (Authorized Security Audit)"},
        ) as client:
            baseline = await client.get(url, timeout=REQUEST_TIMEOUT)
            params = _discover_params(url, baseline.text)
            raw["params_tested"] = params

            if not params:
                findings.append(Finding(
                    title="No Injectable Parameters Found",
                    description="No query string parameters or form fields were discovered to test for injection.",
                    severity=Severity.informational,
                    category="Injection",
                    module="sqli_xss",
                    affected_url=url,
                ))
            else:
                semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
                baseline_len = len(baseline.text)
                results = await asyncio.wait_for(
                    asyncio.gather(
                        *[_check_sqli(client, url, p, baseline_len, semaphore) for p in params],
                        *[_check_xss(client, url, p, semaphore) for p in params],
                    ),
                    timeout=timeout,
                )
                findings.extend(f for f in results if f is not None)

    except asyncio.TimeoutError:
        return ScanResult(module="sqli_xss", error="Injection scan timed out")
    except httpx.RequestError as e:
        return ScanResult(module="sqli_xss", error=str(e))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="sqli_xss", findings=findings, raw_data=raw, duration_ms=duration)
