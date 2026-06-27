"""
TLS/SSL Scanner
Validates certificate chain, cipher suites, and protocol versions (read-only).
"""
import ssl
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
from app.services.scanners.base import Finding, ScanResult, Severity


WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON",
    "ADH", "AECDH", "LOW", "EXP",
}


def _check_cert(hostname: str, port: int, timeout: int) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            version = ssock.version()
            return {
                "cert": cert,
                "cipher_name": cipher[0] if cipher else "unknown",
                "cipher_bits": cipher[2] if cipher else 0,
                "protocol_version": version,
            }


async def scan(url: str, timeout: int = 10) -> ScanResult:
    start = time.monotonic()
    findings: list[Finding] = []
    raw: dict = {}

    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        findings.append(Finding(
            title="Site Não Utiliza HTTPS",
            description="A URL do alvo utiliza HTTP em vez de HTTPS, transmitindo dados em texto claro.",
            severity=Severity.critical,
            category="TLS/SSL",
            module="tls",
            affected_url=url,
            evidence={"scheme": parsed.scheme},
            recommendation="Force o uso de HTTPS com um certificado TLS válido e redirecione HTTP para HTTPS.",
            owasp_category="A02:2021 – Cryptographic Failures",
            references=["https://www.ssllabs.com/ssltest/"],
        ))
        duration = int((time.monotonic() - start) * 1000)
        return ScanResult(module="tls", findings=findings, raw_data=raw, duration_ms=duration)

    try:
        info = _check_cert(hostname, port, timeout)
        raw.update(info)
        cert = info.get("cert", {})

        # Protocol version check
        version = info.get("protocol_version", "")
        if version and version in WEAK_PROTOCOLS:
            findings.append(Finding(
                title=f"Protocolo TLS Obsoleto em Uso: {version}",
                description=f"O servidor negociou {version}, que é obsoleto e inseguro.",
                severity=Severity.high,
                category="TLS/SSL",
                module="tls",
                affected_url=url,
                evidence={"protocol": version},
                recommendation="Desabilite TLS 1.0/1.1 e SSLv2/v3. Utilize no mínimo TLS 1.2, com preferência para TLS 1.3.",
                owasp_category="A02:2021 – Cryptographic Failures",
                references=["https://tools.ietf.org/html/rfc8996"],
            ))
        elif version in ("TLSv1.2",):
            findings.append(Finding(
                title="TLS 1.2 em Uso — TLS 1.3 é Preferível",
                description="TLS 1.2 é seguro, mas o TLS 1.3 oferece melhor desempenho e segurança.",
                severity=Severity.informational,
                category="TLS/SSL",
                module="tls",
                affected_url=url,
                evidence={"protocol": version},
                recommendation="Habilite o TLS 1.3 no servidor.",
            ))

        # Cipher strength
        cipher = info.get("cipher_name", "")
        bits = info.get("cipher_bits", 0)
        for weak in WEAK_CIPHERS:
            if weak in cipher.upper():
                findings.append(Finding(
                    title=f"Cifra Fraca Detectada: {cipher}",
                    description=f"A cifra {cipher} é considerada criptograficamente fraca.",
                    severity=Severity.high,
                    category="TLS/SSL",
                    module="tls",
                    affected_url=url,
                    evidence={"cipher": cipher, "bits": bits},
                    recommendation="Desabilite cifras fracas. Utilize AES-GCM ou ChaCha20-Poly1305.",
                    owasp_category="A02:2021 – Cryptographic Failures",
                ))
                break
        if bits and bits < 128:
            findings.append(Finding(
                title="Tamanho de Chave da Cifra Abaixo de 128 bits",
                description=f"O tamanho da chave da cifra é {bits} bits, o que é insuficiente.",
                severity=Severity.high,
                category="TLS/SSL",
                module="tls",
                affected_url=url,
                evidence={"bits": bits},
                recommendation="Utilize cifras com pelo menos 128 bits de chave.",
            ))

        # Certificate expiry
        if cert:
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                try:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    not_after = not_after.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (not_after - now).days
                    raw["cert_expiry_days"] = days_left

                    if days_left < 0:
                        findings.append(Finding(
                            title="Certificado TLS Expirado",
                            description=f"O certificado expirou há {abs(days_left)} dias.",
                            severity=Severity.critical,
                            category="TLS/SSL",
                            module="tls",
                            affected_url=url,
                            evidence={"not_after": not_after_str, "days_left": days_left},
                            recommendation="Renove o certificado TLS imediatamente.",
                        ))
                    elif days_left < 14:
                        findings.append(Finding(
                            title=f"Certificado TLS Expira em {days_left} Dias",
                            description="O certificado está próximo de expirar — a renovação é urgente.",
                            severity=Severity.high,
                            category="TLS/SSL",
                            module="tls",
                            affected_url=url,
                            evidence={"not_after": not_after_str, "days_left": days_left},
                            recommendation="Renove o certificado TLS antes do vencimento.",
                        ))
                    elif days_left < 30:
                        findings.append(Finding(
                            title=f"Certificado TLS Expira em Breve ({days_left} dias)",
                            description="O certificado expirará dentro de 30 dias.",
                            severity=Severity.medium,
                            category="TLS/SSL",
                            module="tls",
                            affected_url=url,
                            evidence={"not_after": not_after_str, "days_left": days_left},
                            recommendation="Agende a renovação do certificado.",
                        ))
                    else:
                        findings.append(Finding(
                            title=f"Certificado TLS Válido ({days_left} dias restantes)",
                            description="O certificado é válido e não está próximo de expirar.",
                            severity=Severity.informational,
                            category="TLS/SSL",
                            module="tls",
                            affected_url=url,
                            evidence={"not_after": not_after_str, "days_left": days_left},
                        ))
                except ValueError:
                    pass

            # Subject CN / SAN check
            subject = dict(x[0] for x in cert.get("subject", []))
            cn = subject.get("commonName", "")
            san_list = [v for _, v in cert.get("subjectAltName", [])]
            raw["cert_cn"] = cn
            raw["cert_san"] = san_list

            if hostname not in (cn, *san_list) and f"*.{'.'.join(hostname.split('.')[1:])}" not in san_list:
                findings.append(Finding(
                    title="Hostname do Certificado Não Corresponde",
                    description=f"O CN/SAN do certificado não cobre o hostname '{hostname}'.",
                    severity=Severity.high,
                    category="TLS/SSL",
                    module="tls",
                    affected_url=url,
                    evidence={"hostname": hostname, "cn": cn, "san": san_list},
                    recommendation="Emita um certificado que cubra todos os hostnames do alvo.",
                ))

    except ssl.SSLError as e:
        findings.append(Finding(
            title="Erro no Handshake TLS",
            description=f"Erro de SSL durante o handshake: {e}",
            severity=Severity.high,
            category="TLS/SSL",
            module="tls",
            affected_url=url,
            recommendation="Revise a configuração de TLS do servidor.",
        ))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return ScanResult(module="tls", error=str(e))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="tls", findings=findings, raw_data=raw, duration_ms=duration)
