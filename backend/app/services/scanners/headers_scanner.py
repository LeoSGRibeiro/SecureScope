"""
HTTP Security Headers Scanner
Analyzes response headers for security misconfigurations (defensive, read-only).
"""
import time
import httpx
from app.services.scanners.base import Finding, ScanResult, Severity

REQUIRED_HEADERS = {
    "strict-transport-security": {
        "title": "Cabeçalho HSTS Ausente",
        "severity": Severity.high,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Adicione 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
    },
    "content-security-policy": {
        "title": "Cabeçalho Content-Security-Policy Ausente",
        "severity": Severity.high,
        "owasp": "A03:2021 – Injection",
        "recommendation": "Defina uma política de CSP estrita para mitigar ataques de XSS e injeção de dados.",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"],
    },
    "x-frame-options": {
        "title": "Cabeçalho X-Frame-Options Ausente",
        "severity": Severity.medium,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Adicione 'X-Frame-Options: DENY' ou 'SAMEORIGIN' para prevenir clickjacking.",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
    },
    "x-content-type-options": {
        "title": "Cabeçalho X-Content-Type-Options Ausente",
        "severity": Severity.low,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Adicione 'X-Content-Type-Options: nosniff'",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
    },
    "referrer-policy": {
        "title": "Cabeçalho Referrer-Policy Ausente",
        "severity": Severity.low,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Adicione 'Referrer-Policy: strict-origin-when-cross-origin'",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
    },
    "permissions-policy": {
        "title": "Cabeçalho Permissions-Policy Ausente",
        "severity": Severity.informational,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Adicione Permissions-Policy para restringir o acesso a recursos do navegador.",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
    },
}

INSECURE_HEADERS = {
    "server": {
        "title": "Exposição da Versão do Servidor via Cabeçalho 'Server'",
        "severity": Severity.low,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Remova ou anonimize o cabeçalho Server para evitar fingerprinting de tecnologia.",
    },
    "x-powered-by": {
        "title": "Exposição de Tecnologia via Cabeçalho 'X-Powered-By'",
        "severity": Severity.low,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Remova o cabeçalho X-Powered-By.",
    },
    "x-aspnet-version": {
        "title": "Versão do ASP.NET Exposta",
        "severity": Severity.medium,
        "owasp": "A05:2021 – Security Misconfiguration",
        "recommendation": "Desabilite a exposição de versão na configuração do ASP.NET.",
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
                    description=f"O cabeçalho '{header_name}' está ausente na resposta HTTP.",
                    severity=meta["severity"],
                    category="Cabeçalhos de Segurança HTTP",
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
                    title="Cabeçalho HSTS Sem max-age",
                    description="O cabeçalho HSTS está presente, mas não possui a diretiva max-age.",
                    severity=Severity.medium,
                    category="Cabeçalhos de Segurança HTTP",
                    module="headers",
                    affected_url=url,
                    evidence={"header_value": hsts_val},
                    recommendation="Inclua 'max-age=31536000' no cabeçalho HSTS.",
                    owasp_category="A05:2021 – Security Misconfiguration",
                ))
            try:
                max_age = int([p for p in hsts_val.split(";") if "max-age" in p][0].split("=")[1].strip())
                if max_age < 15768000:
                    findings.append(Finding(
                        title="HSTS max-age Muito Curto",
                        description=f"O max-age do HSTS é {max_age}s (< 6 meses). Recomenda-se ≥ 31536000s.",
                        severity=Severity.low,
                        category="Cabeçalhos de Segurança HTTP",
                        module="headers",
                        affected_url=url,
                        evidence={"max_age": max_age},
                        recommendation="Defina o max-age para pelo menos 31536000 (1 ano).",
                    ))
            except Exception:
                pass

        # Check for CSP weaknesses
        csp = headers.get("content-security-policy", "")
        if csp:
            if "unsafe-inline" in csp:
                findings.append(Finding(
                    title="CSP Permite 'unsafe-inline'",
                    description="O Content-Security-Policy contém 'unsafe-inline', o que reduz a proteção contra XSS.",
                    severity=Severity.medium,
                    category="Cabeçalhos de Segurança HTTP",
                    module="headers",
                    affected_url=url,
                    evidence={"csp": csp},
                    recommendation="Remova 'unsafe-inline' e utilize nonces ou hashes no lugar.",
                    owasp_category="A03:2021 – Injection",
                ))
            if "unsafe-eval" in csp:
                findings.append(Finding(
                    title="CSP Permite 'unsafe-eval'",
                    description="O Content-Security-Policy contém 'unsafe-eval', permitindo injeção de scripts.",
                    severity=Severity.medium,
                    category="Cabeçalhos de Segurança HTTP",
                    module="headers",
                    affected_url=url,
                    evidence={"csp": csp},
                    recommendation="Remova 'unsafe-eval' do CSP.",
                    owasp_category="A03:2021 – Injection",
                ))
            if "* " in csp or csp.strip().endswith("*"):
                findings.append(Finding(
                    title="CSP Contém Origem Wildcard",
                    description="A política de CSP utiliza wildcard '*', o que compromete a proteção.",
                    severity=Severity.medium,
                    category="Cabeçalhos de Segurança HTTP",
                    module="headers",
                    affected_url=url,
                    evidence={"csp": csp},
                    recommendation="Substitua origens wildcard por origens específicas e confiáveis.",
                ))

        # Check for information-leaking headers
        for h, meta in INSECURE_HEADERS.items():
            if h in headers:
                findings.append(Finding(
                    title=meta["title"],
                    description=f"O cabeçalho '{h}: {headers[h]}' revela detalhes de tecnologia.",
                    severity=meta["severity"],
                    category="Exposição de Informações",
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
                title="Resposta Potencialmente Cacheável",
                description="O cabeçalho Cache-Control não impede o cache de conteúdo potencialmente sensível.",
                severity=Severity.informational,
                category="Cabeçalhos de Segurança HTTP",
                module="headers",
                affected_url=url,
                evidence={"cache_control": cache or "(não definido)"},
                recommendation="Adicione 'Cache-Control: no-store, private' para páginas sensíveis.",
            ))

    except httpx.TimeoutException:
        return ScanResult(module="headers", error=f"A requisição expirou após {timeout}s")
    except httpx.RequestError as e:
        return ScanResult(module="headers", error=str(e))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="headers", findings=findings, raw_data=raw, duration_ms=duration)
