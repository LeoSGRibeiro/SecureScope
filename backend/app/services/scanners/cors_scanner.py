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
            headers={"User-Agent": "SecureScope-Scanner/1.0 (Authorized Security Audit)"},
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
                                title="CORS com Origem Wildcard e Credenciais Permitidas",
                                description="ACAO: * combinado com ACAC: true é rejeitado pelos navegadores, mas indica uma má configuração.",
                                severity=Severity.medium,
                                category="CORS",
                                module="cors",
                                affected_url=url,
                                evidence={"acao": acao, "acac": acac, "origin_probe": origin},
                                recommendation="Não combine origem wildcard com credenciais. Especifique origens explícitas.",
                                owasp_category="A01:2021 – Broken Access Control",
                                references=["https://portswigger.net/web-security/cors"],
                            ))
                        else:
                            findings.append(Finding(
                                title="CORS com Origem Wildcard (Access-Control-Allow-Origin: *)",
                                description="Qualquer origem pode ler as respostas. Aceitável para APIs públicas; arriscado para endpoints autenticados.",
                                severity=Severity.low,
                                category="CORS",
                                module="cors",
                                affected_url=url,
                                evidence={"acao": acao},
                                recommendation="Restrinja o ACAO a origens confiáveis em endpoints autenticados ou sensíveis.",
                            ))

                    elif acao == origin and origin != "null":
                        sev = Severity.high if acac.lower() == "true" else Severity.medium
                        findings.append(Finding(
                            title=f"CORS Reflete Origem Arbitrária{' + Credenciais' if acac.lower() == 'true' else ''}",
                            description=(
                                f"O servidor refletiu a origem de teste '{origin}' no cabeçalho ACAO"
                                + (" e permite credenciais, possibilitando requisições autenticadas cross-origin." if acac.lower() == "true" else ".")
                            ),
                            severity=sev,
                            category="CORS",
                            module="cors",
                            affected_url=url,
                            evidence={"acao": acao, "acac": acac, "origin_probe": origin},
                            recommendation="Valide o Origin contra uma lista de permissões estrita. Nunca reflita origens arbitrárias.",
                            owasp_category="A01:2021 – Broken Access Control",
                            references=["https://portswigger.net/web-security/cors"],
                        ))

                    elif acao == "null":
                        findings.append(Finding(
                            title="CORS Permite Origem 'null'",
                            description="O servidor aceita a origem 'null', que pode ser disparada a partir de iframes em sandbox.",
                            severity=Severity.medium,
                            category="CORS",
                            module="cors",
                            affected_url=url,
                            evidence={"acao": acao},
                            recommendation="Não permita a origem 'null' na política de CORS.",
                            owasp_category="A01:2021 – Broken Access Control",
                        ))

                    # Dangerous methods
                    dangerous = {"DELETE", "PUT", "PATCH"}
                    allowed_methods = {m.strip().upper() for m in acam.split(",")} if acam else set()
                    exposed_dangerous = dangerous & allowed_methods
                    if exposed_dangerous:
                        findings.append(Finding(
                            title=f"CORS Permite Métodos Perigosos: {', '.join(exposed_dangerous)}",
                            description=f"Os seguintes métodos HTTP são permitidos cross-origin: {', '.join(exposed_dangerous)}",
                            severity=Severity.medium,
                            category="CORS",
                            module="cors",
                            affected_url=url,
                            evidence={"allowed_methods": acam},
                            recommendation="Restrinja os métodos permitidos no CORS ao mínimo necessário.",
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
            title="Política de CORS Aparenta Ser Restritiva",
            description="Nenhuma má configuração perigosa de CORS foi detectada com os testes padrão.",
            severity=Severity.informational,
            category="CORS",
            module="cors",
            affected_url=url,
        ))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="cors", findings=findings, raw_data=raw, duration_ms=duration)
