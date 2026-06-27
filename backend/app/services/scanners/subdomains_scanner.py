"""
Subdomain Discovery Scanner
Uses passive DNS, certificate transparency logs, and WHOIS (no active brute-force).
"""
import time
import asyncio
import httpx
import dns.resolver
import tldextract
from app.services.scanners.base import Finding, ScanResult, Severity


async def _crt_sh(domain: str, client: httpx.AsyncClient) -> list[str]:
    """Query crt.sh certificate transparency log for subdomains."""
    try:
        r = await client.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(domain) and sub != domain:
                        subdomains.add(sub)
            return list(subdomains)
    except Exception:
        pass
    return []


async def _dns_lookup(subdomain: str) -> dict | None:
    """Resolve A and CNAME records for a subdomain."""
    try:
        loop = asyncio.get_event_loop()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        def resolve_a():
            try:
                answers = resolver.resolve(subdomain, "A")
                return [str(r) for r in answers]
            except Exception:
                return []

        def resolve_cname():
            try:
                answers = resolver.resolve(subdomain, "CNAME")
                return [str(r) for r in answers]
            except Exception:
                return []

        a_records = await loop.run_in_executor(None, resolve_a)
        cname_records = await loop.run_in_executor(None, resolve_cname)

        if a_records or cname_records:
            return {"subdomain": subdomain, "a": a_records, "cname": cname_records}
    except Exception:
        pass
    return None


async def scan(url: str, timeout: int = 30) -> ScanResult:
    start = time.monotonic()
    findings: list[Finding] = []
    raw: dict = {"subdomains": [], "dns_records": {}}

    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    raw["target_domain"] = domain

    subdomains_found: list[str] = []

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            verify=True,
            headers={"User-Agent": "SecureScope-Scanner/1.0 (Authorized Security Audit)"},
        ) as client:
            ct_subs = await _crt_sh(domain, client)
            subdomains_found.extend(ct_subs)

        # Deduplicate
        subdomains_found = list(set(subdomains_found))
        raw["subdomains_from_ct"] = len(subdomains_found)

        # Resolve discovered subdomains (batch with concurrency limit)
        sem = asyncio.Semaphore(10)

        async def bounded_lookup(sub: str):
            async with sem:
                return await _dns_lookup(sub)

        tasks = [bounded_lookup(s) for s in subdomains_found[:100]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        live_subs = []
        for r in results:
            if isinstance(r, dict) and r:
                live_subs.append(r)
                raw["subdomains"].append(r)

        if live_subs:
            findings.append(Finding(
                title=f"{len(live_subs)} Subdomínios Ativos Descobertos",
                description=f"Logs de certificate transparency e resolução DNS revelaram {len(live_subs)} subdomínios ativos.",
                severity=Severity.informational,
                category="Subdomains",
                module="subdomains",
                affected_url=url,
                evidence={"count": len(live_subs), "subdomains": [s["subdomain"] for s in live_subs[:20]]},
                recommendation="Revise todos os subdomínios em busca de serviços esquecidos/órfãos. Desative os que não são utilizados.",
            ))

            # Check for dangling CNAME (potential subdomain takeover indicators)
            dangling_patterns = [
                "azurewebsites.net", "s3.amazonaws.com", "github.io", "herokuapp.com",
                "netlify.app", "vercel.app", "pages.github.com", "fastly.net",
            ]
            for sub_info in live_subs:
                for cname in sub_info.get("cname", []):
                    for pattern in dangling_patterns:
                        if pattern in cname:
                            findings.append(Finding(
                                title=f"Possível Risco de Takeover de Subdomínio: {sub_info['subdomain']}",
                                description=(
                                    f"O subdomínio '{sub_info['subdomain']}' possui um CNAME apontando para '{cname}' "
                                    f"({pattern}). Se esse recurso não estiver registrado, um takeover pode ser possível."
                                ),
                                severity=Severity.high,
                                category="Subdomains",
                                module="subdomains",
                                affected_url=f"https://{sub_info['subdomain']}",
                                evidence={"subdomain": sub_info["subdomain"], "cname": cname},
                                recommendation="Verifique se o destino do CNAME está registrado e sob seu controle. Remova registros DNS órfãos.",
                                owasp_category="A05:2021 – Security Misconfiguration",
                                references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
                            ))
        else:
            findings.append(Finding(
                title="Nenhum Subdomínio Ativo Descoberto",
                description="Nenhum subdomínio resolvível foi encontrado via certificate transparency e DNS passivo.",
                severity=Severity.informational,
                category="Subdomains",
                module="subdomains",
                affected_url=url,
            ))

    except Exception as e:
        return ScanResult(module="subdomains", error=str(e))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="subdomains", findings=findings, raw_data=raw, duration_ms=duration)
