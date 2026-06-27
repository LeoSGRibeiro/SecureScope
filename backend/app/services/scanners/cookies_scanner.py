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
                title="Nenhum Cookie Detectado",
                description="Nenhum cabeçalho Set-Cookie foi encontrado na resposta. Se a aplicação usa sessões, verifique se os cookies estão sendo definidos.",
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
                    title=f"Cookie '{name}' Sem o Atributo HttpOnly",
                    description=f"O cookie '{name}' é acessível via JavaScript (sem HttpOnly). Isso possibilita roubo de sessão via XSS.",
                    severity=Severity.medium,
                    category="Cookies",
                    module="cookies",
                    affected_url=url,
                    evidence={"cookie_name": name, "raw_header": cookie_str},
                    recommendation=f"Adicione o atributo 'HttpOnly' ao cookie '{name}'.",
                    owasp_category="A02:2021 – Cryptographic Failures",
                    references=["https://owasp.org/www-community/HttpOnly"],
                ))

            if is_https and "secure" not in attrs_lower:
                findings.append(Finding(
                    title=f"Cookie '{name}' Sem o Atributo Secure",
                    description=f"O cookie '{name}' pode ser transmitido por conexões HTTP não criptografadas.",
                    severity=Severity.medium,
                    category="Cookies",
                    module="cookies",
                    affected_url=url,
                    evidence={"cookie_name": name, "raw_header": cookie_str},
                    recommendation=f"Adicione o atributo 'Secure' ao cookie '{name}'.",
                    owasp_category="A02:2021 – Cryptographic Failures",
                ))

            samesite_attrs = [p for p in attrs_lower if "samesite" in p]
            if not samesite_attrs:
                findings.append(Finding(
                    title=f"Cookie '{name}' Sem o Atributo SameSite",
                    description=f"O cookie '{name}' não possui o atributo SameSite, ficando vulnerável a ataques de CSRF.",
                    severity=Severity.medium,
                    category="Cookies",
                    module="cookies",
                    affected_url=url,
                    evidence={"cookie_name": name, "raw_header": cookie_str},
                    recommendation=f"Adicione 'SameSite=Strict' ou 'SameSite=Lax' ao cookie '{name}'.",
                    owasp_category="A01:2021 – Broken Access Control",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
                ))
            else:
                samesite_val = samesite_attrs[0].split("=")[-1].strip() if "=" in samesite_attrs[0] else ""
                if samesite_val == "none" and "secure" not in attrs_lower:
                    findings.append(Finding(
                        title=f"Cookie '{name}' com SameSite=None Sem Secure",
                        description="SameSite=None exige o atributo Secure; caso contrário, navegadores modernos irão rejeitar o cookie.",
                        severity=Severity.medium,
                        category="Cookies",
                        module="cookies",
                        affected_url=url,
                        evidence={"cookie_name": name, "raw_header": cookie_str},
                        recommendation="Adicione o atributo Secure quando usar SameSite=None.",
                    ))

            # Session cookies without expiry — informational
            has_expiry = any("expires=" in p or "max-age=" in p for p in attrs_lower)
            if not has_expiry and ("session" in name.lower() or "auth" in name.lower() or "token" in name.lower()):
                findings.append(Finding(
                    title=f"Cookie de Sessão '{name}' Sem Expiração",
                    description="O cookie de sessão não possui data de expiração; ele persiste até o navegador ser fechado.",
                    severity=Severity.informational,
                    category="Cookies",
                    module="cookies",
                    affected_url=url,
                    evidence={"cookie_name": name},
                    recommendation="Defina um Max-Age ou Expires explícito para cookies de sessão.",
                ))

    except httpx.TimeoutException:
        return ScanResult(module="cookies", error=f"A requisição expirou após {timeout}s")
    except httpx.RequestError as e:
        return ScanResult(module="cookies", error=str(e))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="cookies", findings=findings, raw_data=raw, duration_ms=duration)
