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
            title="Site Not Using HTTPS",
            description="The target URL uses HTTP instead of HTTPS, transmitting data in cleartext.",
            severity=Severity.critical,
            category="TLS/SSL",
            module="tls",
            affected_url=url,
            evidence={"scheme": parsed.scheme},
            recommendation="Enforce HTTPS with a valid TLS certificate and redirect HTTP to HTTPS.",
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
                title=f"Deprecated TLS Protocol in Use: {version}",
                description=f"The server negotiated {version}, which is deprecated and insecure.",
                severity=Severity.high,
                category="TLS/SSL",
                module="tls",
                affected_url=url,
                evidence={"protocol": version},
                recommendation="Disable TLS 1.0/1.1 and SSLv2/v3. Use TLS 1.2 minimum, prefer TLS 1.3.",
                owasp_category="A02:2021 – Cryptographic Failures",
                references=["https://tools.ietf.org/html/rfc8996"],
            ))
        elif version in ("TLSv1.2",):
            findings.append(Finding(
                title="TLS 1.2 in Use — TLS 1.3 Preferred",
                description="TLS 1.2 is secure but TLS 1.3 offers better performance and security.",
                severity=Severity.informational,
                category="TLS/SSL",
                module="tls",
                affected_url=url,
                evidence={"protocol": version},
                recommendation="Enable TLS 1.3 on the server.",
            ))

        # Cipher strength
        cipher = info.get("cipher_name", "")
        bits = info.get("cipher_bits", 0)
        for weak in WEAK_CIPHERS:
            if weak in cipher.upper():
                findings.append(Finding(
                    title=f"Weak Cipher Suite Detected: {cipher}",
                    description=f"The cipher {cipher} is considered cryptographically weak.",
                    severity=Severity.high,
                    category="TLS/SSL",
                    module="tls",
                    affected_url=url,
                    evidence={"cipher": cipher, "bits": bits},
                    recommendation="Disable weak cipher suites. Use AES-GCM or ChaCha20-Poly1305.",
                    owasp_category="A02:2021 – Cryptographic Failures",
                ))
                break
        if bits and bits < 128:
            findings.append(Finding(
                title="Cipher Key Length Below 128 bits",
                description=f"Cipher key length is {bits} bits, which is insufficient.",
                severity=Severity.high,
                category="TLS/SSL",
                module="tls",
                affected_url=url,
                evidence={"bits": bits},
                recommendation="Use ciphers with at least 128-bit key length.",
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
                            title="TLS Certificate Expired",
                            description=f"Certificate expired {abs(days_left)} days ago.",
                            severity=Severity.critical,
                            category="TLS/SSL",
                            module="tls",
                            affected_url=url,
                            evidence={"not_after": not_after_str, "days_left": days_left},
                            recommendation="Renew the TLS certificate immediately.",
                        ))
                    elif days_left < 14:
                        findings.append(Finding(
                            title=f"TLS Certificate Expiring in {days_left} Days",
                            description="Certificate is about to expire — renewal is urgent.",
                            severity=Severity.high,
                            category="TLS/SSL",
                            module="tls",
                            affected_url=url,
                            evidence={"not_after": not_after_str, "days_left": days_left},
                            recommendation="Renew TLS certificate before expiry.",
                        ))
                    elif days_left < 30:
                        findings.append(Finding(
                            title=f"TLS Certificate Expiring Soon ({days_left} days)",
                            description="Certificate will expire within 30 days.",
                            severity=Severity.medium,
                            category="TLS/SSL",
                            module="tls",
                            affected_url=url,
                            evidence={"not_after": not_after_str, "days_left": days_left},
                            recommendation="Schedule certificate renewal.",
                        ))
                    else:
                        findings.append(Finding(
                            title=f"TLS Certificate Valid ({days_left} days remaining)",
                            description="Certificate is valid and not near expiry.",
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
                    title="Certificate Hostname Mismatch",
                    description=f"Certificate CN/SAN does not cover hostname '{hostname}'.",
                    severity=Severity.high,
                    category="TLS/SSL",
                    module="tls",
                    affected_url=url,
                    evidence={"hostname": hostname, "cn": cn, "san": san_list},
                    recommendation="Issue a certificate that covers all target hostnames.",
                ))

    except ssl.SSLError as e:
        findings.append(Finding(
            title="TLS Handshake Error",
            description=f"SSL error during handshake: {e}",
            severity=Severity.high,
            category="TLS/SSL",
            module="tls",
            affected_url=url,
            recommendation="Review server TLS configuration.",
        ))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return ScanResult(module="tls", error=str(e))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="tls", findings=findings, raw_data=raw, duration_ms=duration)
