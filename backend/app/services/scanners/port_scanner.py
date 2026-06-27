"""
Port/Service Scanner
Non-destructive TCP connect scan against a fixed list of commonly
sensitive ports. Identifies obviously exposed services without any
banner grabbing or exploitation.
"""
import asyncio
import ipaddress
import time
from urllib.parse import urlparse
from app.services.scanners.base import Finding, ScanResult, Severity

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
                1433, 3306, 3389, 5432, 6379, 8080, 8443, 27017]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    587: "SMTP (Submission)", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

# Database/admin services that should never be reachable from the internet.
HIGH_RISK_PORTS = {1433, 3306, 3389, 5432, 6379, 27017, 23, 445}
LOW_RISK_PORTS = {80, 443, 8080, 8443}

CONNECT_TIMEOUT = 3
MAX_CONCURRENCY = 10


def _extract_host(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"//{url}")
    host = parsed.hostname or url.split("/")[0].split(":")[0]
    return host


def _is_blocked_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except ValueError:
        return host.lower() in {"localhost", "0.0.0.0", "metadata.google.internal"}


async def _check_port(host: str, port: int, semaphore: asyncio.Semaphore) -> bool:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False


def _severity_for_port(port: int) -> Severity:
    if port in HIGH_RISK_PORTS:
        return Severity.high
    if port in LOW_RISK_PORTS:
        return Severity.informational
    return Severity.medium


async def scan(url: str, timeout: int = 15) -> ScanResult:
    start = time.monotonic()
    findings: list[Finding] = []
    raw: dict = {"scanned_ports": COMMON_PORTS, "open_ports": []}

    host = _extract_host(url)
    if not host or _is_blocked_host(host):
        return ScanResult(module="port_scan", error="O host do alvo é interno/privado; o scan foi recusado")

    try:
        semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
        results = await asyncio.wait_for(
            asyncio.gather(*[_check_port(host, port, semaphore) for port in COMMON_PORTS]),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return ScanResult(module="port_scan", error="A varredura de portas expirou")
    except Exception as e:
        return ScanResult(module="port_scan", error=str(e))

    open_ports = [port for port, is_open in zip(COMMON_PORTS, results) if is_open]
    raw["open_ports"] = open_ports

    for port in open_ports:
        service = SERVICE_NAMES.get(port, "Unknown")
        severity = _severity_for_port(port)
        if severity == Severity.informational:
            findings.append(Finding(
                title=f"Porta Aberta {port} ({service})",
                description=f"A porta {port}/tcp ({service}) está acessível pela internet.",
                severity=severity,
                category="Network Exposure",
                module="port_scan",
                affected_url=host,
                evidence={"port": port, "service": service},
            ))
        else:
            findings.append(Finding(
                title=f"Serviço Exposto: {service} (porta {port})",
                description=(
                    f"A porta {port}/tcp ({service}) está acessível pela internet. "
                    "Serviços de banco de dados, administração remota e legados não devem ser "
                    "expostos diretamente; isso aumenta a superfície de ataque."
                ),
                severity=severity,
                category="Network Exposure",
                module="port_scan",
                affected_url=host,
                evidence={"port": port, "service": service},
                recommendation=(
                    f"Restrinja o acesso à porta {port} a redes confiáveis (VPN/firewall/security group) "
                    "ou desabilite o serviço completamente se não for necessário."
                ),
                owasp_category="A05:2021 – Security Misconfiguration",
            ))

    if not findings:
        findings.append(Finding(
            title="Nenhuma Porta Comumente Exposta Detectada",
            description=f"Nenhuma das {len(COMMON_PORTS)} portas comumente testadas respondeu.",
            severity=Severity.informational,
            category="Network Exposure",
            module="port_scan",
            affected_url=host,
        ))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="port_scan", findings=findings, raw_data=raw, duration_ms=duration)
