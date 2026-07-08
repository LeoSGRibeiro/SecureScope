"""
Deep Port Scanner with Banner Grabbing (INTRUSIVE)
Extends the lightweight port_scanner.py (21 ports, TCP-connect only) to a
larger port list with best-effort banner grabbing for service/version
fingerprinting. Still non-destructive (read-only banner read, optional
HEAD request for HTTP-like services), but probes far more ports and
takes noticeably longer, which is why it's a separate module rather than
a change to the already-shipped port_scan module.
"""
import asyncio
import time
from app.services.scanners.base import Finding, ScanResult, Severity
from app.services.scanners.port_scanner import (
    _extract_host, _is_blocked_host, SERVICE_NAMES as BASE_SERVICE_NAMES,
)

DEEP_PORTS = sorted(set([
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
    1433, 3306, 3389, 5432, 6379, 8080, 8443, 27017,
    20, 69, 79, 111, 123, 135, 137, 138, 139, 161, 162, 389,
    512, 513, 514, 515, 520, 548, 623, 631, 636, 873, 902, 989, 990,
    1025, 1080, 1100, 1194, 1198, 1521, 1723, 2049, 2082, 2083, 2086, 2087,
    2095, 2096, 2181, 2375, 2376, 3000, 3268, 3269, 4444, 4567, 5000, 5001,
    5060, 5061, 5666, 5900, 5901, 5985, 5986, 6000, 6443, 7001, 7002,
    8000, 8008, 8081, 8082, 8088, 8090, 8888, 9000, 9001, 9042, 9090,
    9091, 9092, 9100, 9200, 9300, 9418, 10000, 11211, 15672, 24800,
]))

EXTRA_SERVICE_NAMES = {
    20: "FTP-DATA", 69: "TFTP", 79: "Finger", 111: "RPCBind", 123: "NTP",
    135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    161: "SNMP", 162: "SNMP-Trap", 389: "LDAP", 512: "rexec", 513: "rlogin",
    514: "syslog", 515: "LPD", 520: "RIP", 548: "AFP", 623: "IPMI",
    631: "IPP/CUPS", 636: "LDAPS", 873: "rsync", 902: "VMware-Auth",
    989: "FTPS-DATA", 990: "FTPS", 1025: "NFS/RPC", 1080: "SOCKS",
    1100: "MCTP", 1194: "OpenVPN", 1198: "CajoDiscovery", 1521: "Oracle-DB",
    1723: "PPTP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    2086: "WHM", 2087: "WHM-SSL", 2095: "cPanel-Webmail", 2096: "cPanel-Webmail-SSL",
    2181: "Zookeeper", 2375: "Docker", 2376: "Docker-TLS", 3000: "Dev-HTTP",
    3268: "LDAP-GC", 3269: "LDAP-GC-SSL", 4444: "Metasploit/Generic", 4567: "Sinatra",
    5000: "Dev-HTTP", 5001: "Dev-HTTP-Alt", 5060: "SIP", 5061: "SIP-TLS",
    5666: "NRPE", 5900: "VNC", 5901: "VNC-1", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6000: "X11", 6443: "Kubernetes-API", 7001: "WebLogic", 7002: "WebLogic-SSL",
    8000: "HTTP-Alt", 8008: "HTTP-Alt", 8081: "HTTP-Alt", 8082: "HTTP-Alt",
    8088: "HTTP-Alt", 8090: "HTTP-Alt", 8888: "HTTP-Alt", 9000: "PHP-FPM/SonarQube",
    9001: "HTTP-Alt", 9042: "Cassandra", 9090: "Prometheus", 9091: "Prometheus-Alt",
    9092: "Kafka", 9100: "JetDirect/Printer", 9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
    9418: "Git", 10000: "Webmin", 11211: "Memcached", 15672: "RabbitMQ-Mgmt", 24800: "Synergy",
}

SERVICE_NAMES = {**EXTRA_SERVICE_NAMES, **BASE_SERVICE_NAMES}

HIGH_RISK_PORTS = {
    1433, 3306, 3389, 5432, 6379, 27017, 23, 445,
    161, 389, 636, 2375, 2376, 5900, 5901, 5985, 5986,
    6443, 9200, 9300, 11211, 15672, 902, 512, 513, 514,
}
LOW_RISK_PORTS = {80, 443, 8080, 8443}

CONNECT_TIMEOUT = 3
BANNER_READ_TIMEOUT = 2
MAX_CONCURRENCY = 15

HTTP_LIKE_PORTS = {80, 443, 3000, 5000, 5001, 7001, 7002, 8000, 8008, 8080,
                   8081, 8082, 8088, 8090, 8443, 8888, 9000, 9001, 9090, 9091, 10000}


async def _grab_banner(host: str, port: int) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT)
    except Exception:
        return ""

    banner = ""
    try:
        if port in HTTP_LIKE_PORTS:
            try:
                writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                await writer.drain()
            except Exception:
                pass
        data = await asyncio.wait_for(reader.read(1024), timeout=BANNER_READ_TIMEOUT)
        banner = data.decode(errors="replace").strip().splitlines()[0] if data else ""
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return banner


async def _check_port(host: str, port: int, semaphore: asyncio.Semaphore) -> tuple[int, str] | None:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            return None
        banner = await _grab_banner(host, port)
        return port, banner


def _severity_for_port(port: int) -> Severity:
    if port in HIGH_RISK_PORTS:
        return Severity.high
    if port in LOW_RISK_PORTS:
        return Severity.informational
    return Severity.medium


async def scan(url: str, timeout: int = 45) -> ScanResult:
    start = time.monotonic()
    findings: list[Finding] = []
    raw: dict = {"scanned_ports": DEEP_PORTS, "open_ports": []}

    host = _extract_host(url)
    if not host or _is_blocked_host(host):
        return ScanResult(module="port_scan_deep", error="Target host is internal/private; scan refused")

    try:
        semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
        results = await asyncio.wait_for(
            asyncio.gather(*[_check_port(host, port, semaphore) for port in DEEP_PORTS]),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return ScanResult(module="port_scan_deep", error="Deep port scan timed out")
    except Exception as e:
        return ScanResult(module="port_scan_deep", error=str(e))

    open_results = [r for r in results if r is not None]
    raw["open_ports"] = [{"port": p, "banner": b[:200]} for p, b in open_results]

    for port, banner in open_results:
        service = SERVICE_NAMES.get(port, "Unknown")
        severity = _severity_for_port(port)
        banner_snippet = banner[:120] if banner else "(no banner)"

        if severity == Severity.informational:
            findings.append(Finding(
                title=f"Open Port {port} ({service}) — Banner: {banner_snippet}",
                description=f"Port {port}/tcp ({service}) is reachable from the internet.",
                severity=severity,
                category="Network Exposure",
                module="port_scan_deep",
                affected_url=host,
                evidence={"port": port, "service": service, "banner": banner},
            ))
        else:
            findings.append(Finding(
                title=f"Exposed Service: {service} (port {port}) — Banner: {banner_snippet}",
                description=(
                    f"Port {port}/tcp ({service}) is reachable from the internet. "
                    "Database, remote-administration, and infrastructure services should not be "
                    "directly exposed; this increases the attack surface."
                ),
                severity=severity,
                category="Network Exposure",
                module="port_scan_deep",
                affected_url=host,
                evidence={"port": port, "service": service, "banner": banner},
                recommendation=(
                    f"Restrict access to port {port} to trusted networks (VPN/firewall/security group) "
                    "or disable the service entirely if not required."
                ),
                owasp_category="A05:2021 – Security Misconfiguration",
            ))

    if not findings:
        findings.append(Finding(
            title="No Open Ports Detected",
            description=f"None of the {len(DEEP_PORTS)} probed ports responded.",
            severity=Severity.informational,
            category="Network Exposure",
            module="port_scan_deep",
            affected_url=host,
        ))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="port_scan_deep", findings=findings, raw_data=raw, duration_ms=duration)
