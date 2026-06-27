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
    (r"SQL syntax.*MySQL", "Erro de SQL do MySQL Exposto", Severity.high, "A03:2021 – Injection"),
    (r"Warning:.*mysql_", "Warning PHP do MySQL Exposto", Severity.high, "A03:2021 – Injection"),
    (r"ORA-[0-9]{5}", "Erro do Banco Oracle Exposto", Severity.high, "A03:2021 – Injection"),
    (r"Microsoft OLE DB.*SQL Server", "Erro do MSSQL OLE DB Exposto", Severity.high, "A03:2021 – Injection"),
    (r"SQLSTATE\[", "Erro de SQL State Exposto", Severity.high, "A03:2021 – Injection"),
    (r"Traceback \(most recent call last\)", "Stack Trace do Python Exposto", Severity.medium, "A05:2021 – Security Misconfiguration"),
    (r"at .+\(.*\.java:\d+\)", "Stack Trace do Java Exposto", Severity.medium, "A05:2021 – Security Misconfiguration"),
    (r"Exception in thread", "Exceção do Java Exposta", Severity.medium, "A05:2021 – Security Misconfiguration"),
    (r"Parse error:.*in .*on line", "Erro de Parse do PHP Exposto", Severity.medium, "A05:2021 – Security Misconfiguration"),
    (r"Notice:.*Undefined variable", "Notice do PHP Exposto", Severity.low, "A05:2021 – Security Misconfiguration"),
    (r"Fatal error:.*in .*on line", "Erro Fatal do PHP Exposto", Severity.high, "A05:2021 – Security Misconfiguration"),
    (r"\bpassword\b.*=.*\S+", "Possível Credencial no Corpo da Resposta", Severity.critical, "A02:2021 – Cryptographic Failures"),
    (r"api[_-]?key.*[:=].*[A-Za-z0-9]{16,}", "Chave de API Exposta na Resposta", Severity.critical, "A02:2021 – Cryptographic Failures"),
    (r"Authorization: Bearer [A-Za-z0-9\-_\.]+", "Token Bearer Exposto no Corpo da Resposta", Severity.critical, "A02:2021 – Cryptographic Failures"),
]

# Patterns for reflected content in response that may indicate XSS reflection points
XSS_INDICATORS = [
    r"<script>alert\(",
    r"javascript:void",
    r"onerror=",
    r"onload=",
]

SENSITIVE_FILE_PATHS = [
    ("/.git/HEAD", "Repositório Git Exposto"),
    ("/.env", "Arquivo .env Exposto"),
    ("/config.php", "Arquivo de Configuração PHP Exposto"),
    ("/wp-config.php", "Configuração do WordPress Exposta"),
    ("/configuration.php", "Configuração do Joomla Exposta"),
    ("/settings.py", "Settings do Django Exposto"),
    ("/web.config", "web.config do ASP.NET Exposto"),
    ("/composer.json", "Manifesto Composer do PHP Exposto"),
    ("/package.json", "Manifesto de Pacotes Node.js Exposto"),
    ("/Dockerfile", "Dockerfile Exposto"),
    ("/docker-compose.yml", "Docker Compose Exposto"),
    ("/backup.sql", "Backup SQL Exposto"),
    ("/dump.sql", "Dump SQL Exposto"),
    ("/robots.txt", "robots.txt (informativo)"),
    ("/sitemap.xml", "sitemap.xml (informativo)"),
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
            headers={"User-Agent": "SecureScope-Scanner/1.0 (Authorized Security Audit)"},
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
                        description=f"O corpo da resposta contém um padrão que sugere vazamento de informações: '{snippet[:80]}...'",
                        severity=sev,
                        category="Information Disclosure",
                        module="owasp",
                        affected_url=url,
                        evidence={"pattern": pattern, "snippet": snippet},
                        recommendation="Suprima mensagens de erro detalhadas em produção. Utilize páginas de erro genéricas.",
                        owasp_category=owasp,
                    ))

            # Check for XSS reflection indicators (informational only — no injection attempted)
            for xss_pat in XSS_INDICATORS:
                if re.search(xss_pat, body, re.IGNORECASE):
                    findings.append(Finding(
                        title="Possível Indicador de XSS Refletido na Resposta",
                        description="O corpo da resposta contém padrões associados a payloads de cross-site scripting. Verificação manual é necessária.",
                        severity=Severity.medium,
                        category="XSS Indicators",
                        module="owasp",
                        affected_url=url,
                        evidence={"pattern": xss_pat},
                        recommendation="Revise a codificação de saída e implemente um CSP estrito. Nenhum teste ativo foi realizado.",
                        owasp_category="A03:2021 – Injection",
                    ))

            # Directory listing detection
            if "Index of /" in body or "Directory listing" in body.lower():
                findings.append(Finding(
                    title="Listagem de Diretório Habilitada",
                    description="O servidor web está expondo uma listagem de diretório, revelando a estrutura de arquivos.",
                    severity=Severity.medium,
                    category="Information Disclosure",
                    module="owasp",
                    affected_url=url,
                    evidence={"indicator": "Listagem de diretório detectada no corpo da resposta"},
                    recommendation="Desabilite a listagem de diretório na configuração do servidor web.",
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
                        title="Conteúdo Misto Detectado",
                        description=f"A página HTTPS carrega {len(http_resources)} recurso(s) via HTTP.",
                        severity=Severity.medium,
                        category="Mixed Content",
                        module="owasp",
                        affected_url=url,
                        evidence={"http_resources": http_resources[:10]},
                        recommendation="Sirva todos os recursos via HTTPS.",
                        owasp_category="A02:2021 – Cryptographic Failures",
                    ))

            # Check for inline event handlers (potential XSS surface)
            soup = BeautifulSoup(body, "lxml")
            inline_events = soup.find_all(attrs=re.compile(r"^on\w+"))
            if len(inline_events) > 5:
                findings.append(Finding(
                    title=f"Alto Número de Manipuladores de Eventos Inline ({len(inline_events)})",
                    description="Foi detectado um grande número de manipuladores de eventos JavaScript inline. Eles podem contornar o CSP.",
                    severity=Severity.low,
                    category="XSS Indicators",
                    module="owasp",
                    affected_url=url,
                    evidence={"count": len(inline_events)},
                    recommendation="Mova os manipuladores de eventos para scripts externos e utilize um CSP estrito.",
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
                        title="Formulário POST Sem Token CSRF Aparente",
                        description=f"Um formulário POST (action: {action}) não possui um campo de token CSRF detectável.",
                        severity=Severity.medium,
                        category="CSRF",
                        module="owasp",
                        affected_url=url,
                        evidence={"form_action": action, "method": method},
                        recommendation="Adicione token CSRF a todos os formulários POST que alteram estado.",
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
                            description=f"O arquivo '{path}' está publicamente acessível e pode expor informações sensíveis.",
                            severity=sev,
                            category="Information Disclosure",
                            module="owasp",
                            affected_url=f"{base}{path}",
                            evidence={"path": path, "snippet": content_snippet[:200]},
                            recommendation=f"Restrinja o acesso a '{path}'. Remova-o da raiz pública do servidor se não for necessário.",
                            owasp_category="A05:2021 – Security Misconfiguration",
                        ))
                except Exception:
                    pass

    except httpx.TimeoutException:
        return ScanResult(module="owasp", error=f"A requisição expirou após {timeout}s")
    except httpx.RequestError as e:
        return ScanResult(module="owasp", error=str(e))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="owasp", findings=findings, raw_data=raw, duration_ms=duration)
