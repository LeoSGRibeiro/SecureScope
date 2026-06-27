"""
CORS Configuration Scanner
Tests for dangerous CORS misconfigurations using harmless probe requests.
"""
import time
import httpx
from app.services.scanners.base import Finding, ScanResult, Severity

PROBE_ORIGINS = [
    "https://evil.example.com",
    "null",
    "https://attacker.io",
]


async def scan(url: str, timeout: int = 15) -> ScanResult:
    start = time.monotonic()
    findings: list[Finding] = []
    raw: dict = {"probes": []}

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "ThreatLens-Scanner/1.0 (Authorized Security Audit)"},
        ) as client:

            for origin in PROBE_ORIGINS:
                try:
                    response = await client.options(
                        url,
                        headers={
                            "Origin": origin,
                            "Access-Control-Request-Method": "GET",
                            "Access-Control-Request-Headers": "Content-Type",
                        },
                    )
                    acao = response.headers.get("access-control-allow-origin", "")
                    acac = response.headers.get("access-control-allow-credentials", "")
                    acam = response.headers.get("access-control-allow-methods", "")
                    raw["probes"].append({
                        "origin_sent": origin,
                        "acao": acao,
                        "acac": acac,
                        "acam": acam,
                        "status": response.status_code,
                    })

                    if acao == "*":
                        if acac.lower() == "true":
                            findings.append(Finding(
                                title="CORS Wildcard Origin With Credentials Allowed",
                                description="ACAO: * combined with ACAC: true is rejected by browsers but indicates misconfiguration.",
                                severity=Severity.medium,
                                category="CORS",
                                module="cors",
                                affected_url=url,
                                evidence={"acao": acao, "acac": acac, "origin_probe": origin},
                                recommendation="Do not combine wildcard origin with credentials. Specify explicit origins.",
                                owasp_category="A01:2021 – Broken Access Control",
                                references=["https://portswigger.net/web-security/cors"],
                            ))
                        else:
                            findings.append(Finding(
                                title="CORS Wildcard Origin (Access-Control-Allow-Origin: *)",
                                description="Any origin can read responses. Acceptable for public APIs; risky for authenticated endpoints.",
                                severity=Severity.low,
                                category="CORS",
                                module="cors",
                                affected_url=url,
                                evidence={"acao": acao},
                                recommendation="Restrict ACAO to trusted origins for authenticated or sensitive endpoints.",
                            ))

                    elif acao == origin and origin != "null":
                        sev = Severity.high if acac.lower() == "true" else Severity.medium
                        findings.append(Finding(
                            title=f"CORS Reflects Arbitrary Origin{'  + Credentials' if acac.lower() == 'true' else ''}",
                            description=(
                                f"Server reflected the probe origin '{origin}' in ACAO header"
                                + (" and allows credentials, enabling cross-origin authenticated requests." if acac.lower() == "true" else ".")
                            ),
                            severity=sev,
                            category="CORS",
                            module="cors",
                            affected_url=url,
                            evidence={"acao": acao, "acac": acac, "origin_probe": origin},
                            recommendation="Validate Origin against a strict allowlist. Never reflect arbitrary origins.",
                            owasp_category="A01:2021 – Broken Access Control",
                            references=["https://portswigger.net/web-security/cors"],
                        ))

                    elif acao == "null":
                        findings.append(Finding(
                            title="CORS Allows 'null' Origin",
                            description="Server accepts 'null' origin which can be triggered from sandboxed iframes.",
                            severity=Severity.medium,
                            category="CORS",
                            module="cors",
                            affected_url=url,
                            evidence={"acao": acao},
                            recommendation="Do not allow 'null' origin in CORS policy.",
                            owasp_category="A01:2021 – Broken Access Control",
                        ))

                    # Dangerous methods
                    dangerous = {"DELETE", "PUT", "PATCH"}
                    allowed_methods = {m.strip().upper() for m in acam.split(",")} if acam else set()
                    exposed_dangerous = dangerous & allowed_methods
                    if exposed_dangerous:
                        findings.append(Finding(
                            title=f"CORS Allows Dangerous Methods: {', '.join(exposed_dangerous)}",
                            description=f"The following HTTP methods are permitted cross-origin: {', '.join(exposed_dangerous)}",
                            severity=Severity.medium,
                            category="CORS",
                            module="cors",
                            affected_url=url,
                            evidence={"allowed_methods": acam},
                            recommendation="Restrict allowed CORS methods to the minimum required.",
                        ))

                except Exception:
                    pass

            # Also check simple GET response headers
            try:
                response = await client.get(url)
                acao = response.headers.get("access-control-allow-origin", "")
                if acao:
                    raw["get_acao"] = acao
            except Exception:
                pass

    except httpx.RequestError as e:
        return ScanResult(module="cors", error=str(e))

    if not findings:
        findings.append(Finding(
            title="CORS Policy Appears Restrictive",
            description="No dangerous CORS misconfigurations detected with standard probes.",
            severity=Severity.informational,
            category="CORS",
            module="cors",
            affected_url=url,
        ))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="cors", findings=findings, raw_data=raw, duration_ms=duration)
