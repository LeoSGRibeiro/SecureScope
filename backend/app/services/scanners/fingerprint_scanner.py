"""
Technology Fingerprint Scanner
Identifies CMS, frameworks, server software, CDN, and WAF from passive signals.
"""
import re
import time
import httpx
from bs4 import BeautifulSoup
from app.services.scanners.base import Finding, ScanResult, Severity
from app.services.scanners.cve_lookup import search_cves

TECH_SIGNATURES = {
    "WordPress": {
        "patterns": [r"/wp-content/", r"/wp-includes/", r'name="generator" content="WordPress'],
        "header_keys": [],
        "severity": Severity.informational,
    },
    "Drupal": {
        "patterns": [r"Drupal", r"/sites/default/files/", r"drupal\.js"],
        "header_keys": ["x-drupal-cache"],
        "severity": Severity.informational,
    },
    "Joomla": {
        "patterns": [r"/components/com_", r"/templates/", r"Joomla!"],
        "header_keys": [],
        "severity": Severity.informational,
    },
    "Laravel": {
        "patterns": [r"laravel_session", r"csrf_token.*laravel"],
        "header_keys": [],
        "severity": Severity.informational,
    },
    "Django": {
        "patterns": [r"csrfmiddlewaretoken", r"django"],
        "header_keys": [],
        "severity": Severity.informational,
    },
    "Ruby on Rails": {
        "patterns": [r"authenticity_token"],
        "header_keys": ["x-runtime", "x-request-id"],
        "severity": Severity.informational,
    },
    "Next.js": {
        "patterns": [r"__NEXT_DATA__", r"/_next/static/"],
        "header_keys": ["x-nextjs-page"],
        "severity": Severity.informational,
    },
    "React": {
        "patterns": [r"react-root", r"data-reactroot", r"__react"],
        "header_keys": [],
        "severity": Severity.informational,
    },
    "Vue.js": {
        "patterns": [r"data-v-", r"vue\.js", r"vue\.min\.js"],
        "header_keys": [],
        "severity": Severity.informational,
    },
    "Angular": {
        "patterns": [r"ng-version=", r"angular\.js", r"ng-app"],
        "header_keys": [],
        "severity": Severity.informational,
    },
    "jQuery": {
        "patterns": [r"jquery[.-](\d+\.\d+)", r"jQuery v(\d+)"],
        "header_keys": [],
        "severity": Severity.informational,
    },
    "Bootstrap": {
        "patterns": [r"bootstrap\.min\.css", r"bootstrap\.js"],
        "header_keys": [],
        "severity": Severity.informational,
    },
    "Cloudflare": {
        "patterns": [],
        "header_keys": ["cf-ray", "cf-cache-status"],
        "severity": Severity.informational,
    },
    "AWS CloudFront": {
        "patterns": [],
        "header_keys": ["x-amz-cf-id", "x-amz-cf-pop"],
        "severity": Severity.informational,
    },
    "Nginx": {
        "patterns": [],
        "header_keys": [],
        "server_pattern": r"nginx/?(\S*)",
        "severity": Severity.informational,
    },
    "Apache": {
        "patterns": [],
        "header_keys": [],
        "server_pattern": r"Apache/?(\S*)",
        "severity": Severity.informational,
    },
    "IIS": {
        "patterns": [],
        "header_keys": [],
        "server_pattern": r"Microsoft-IIS/(\S+)",
        "severity": Severity.informational,
    },
}

OUTDATED_PATTERNS = {
    "jQuery < 1.12": (r"jquery[.-](\d+)\.(\d+)", lambda m: int(m.group(1)) == 1 and int(m.group(2)) < 12),
    "Bootstrap 3.x": (r"bootstrap[.-]3\.", lambda m: True),
}

# CVE only filled in where a single, unambiguous CVE genuinely covers every
# version matched by the pattern above. "jQuery < 1.12" is always < 3.0.0,
# which CVE-2015-9251 (XSS via cross-domain Ajax without dataType) covers.
# Bootstrap 3.x has several version-specific CVEs (e.g. CVE-2018-14040/41/42)
# but no single CVE applies to the whole 3.x line, so it's left blank rather
# than guessing.
OUTDATED_CVE = {
    "jQuery < 1.12": "CVE-2015-9251",
}

# Best-effort live lookup against the official CVE List (cve.org, via NVD) for
# each outdated library detected above. The keyword is the bare product name —
# NVD's keyword search matches substrings of CVE descriptions, so this can
# surface CVEs for similarly-named plugins, not just the core library. Every
# resulting Finding is worded as "possible, verify applicability" rather than
# a confirmed match for exactly that reason.
CVE_LOOKUP_KEYWORDS = {
    "jQuery < 1.12": "jquery",
    "Bootstrap 3.x": "bootstrap",
}

ADMIN_PATHS = [
    "/admin", "/wp-admin", "/administrator", "/manager",
    "/cpanel", "/.env", "/config.php", "/phpinfo.php",
    "/backup", "/backup.zip", "/db.sql", "/.git/HEAD",
    "/server-status", "/server-info", "/elmah.axd",
]


async def scan(url: str, timeout: int = 15) -> ScanResult:
    start = time.monotonic()
    findings: list[Finding] = []
    raw: dict = {"detected": [], "exposed_paths": []}
    detected_tech: list[str] = []

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "ThreatLens-Scanner/1.0 (Authorized Security Audit)"},
        ) as client:
            response = await client.get(url)
            body = response.text
            headers = {k.lower(): v for k, v in response.headers.items()}
            raw["status_code"] = response.status_code
            raw["content_type"] = headers.get("content-type", "")
            server = headers.get("server", "")

            # Detect technologies
            for tech, sig in TECH_SIGNATURES.items():
                matched = False
                for pattern in sig.get("patterns", []):
                    if re.search(pattern, body, re.IGNORECASE):
                        matched = True
                        break
                if not matched:
                    for h in sig.get("header_keys", []):
                        if h in headers:
                            matched = True
                            break
                if not matched and "server_pattern" in sig:
                    if re.search(sig["server_pattern"], server, re.IGNORECASE):
                        matched = True
                if matched:
                    detected_tech.append(tech)

            raw["detected"] = detected_tech

            if detected_tech:
                findings.append(Finding(
                    title="Technologies Fingerprinted",
                    description=f"Detected: {', '.join(detected_tech)}",
                    severity=Severity.informational,
                    category="Fingerprint",
                    module="fingerprint",
                    affected_url=url,
                    evidence={"technologies": detected_tech, "server": server},
                    recommendation="Review whether detected technology versions are up-to-date.",
                ))

            # Check for outdated libraries in HTML
            for lib_name, (pattern, condition) in OUTDATED_PATTERNS.items():
                m = re.search(pattern, body, re.IGNORECASE)
                if m and condition(m):
                    findings.append(Finding(
                        title=f"Potentially Outdated Library: {lib_name}",
                        description=f"An older version of {lib_name.split(' ')[0]} was detected in the page source.",
                        severity=Severity.medium,
                        category="Fingerprint",
                        module="fingerprint",
                        affected_url=url,
                        evidence={"match": m.group(0)},
                        recommendation=f"Upgrade {lib_name.split(' ')[0]} to the latest stable version.",
                        owasp_category="A06:2021 – Vulnerable and Outdated Components",
                        cve=OUTDATED_CVE.get(lib_name, ""),
                    ))

                    keyword = CVE_LOOKUP_KEYWORDS.get(lib_name)
                    if keyword:
                        cve_matches = await search_cves(keyword, max_results=2, timeout=25.0)
                        for cve in cve_matches:
                            findings.append(Finding(
                                title=f"Possible Related CVE for {lib_name.split(' ')[0]} (Verify Applicability): {cve['id']}",
                                description=(
                                    f"While searching the public CVE List for '{keyword}', {cve['id']} was found: "
                                    f"{cve['description']} This is a keyword match and may refer to a different "
                                    "library or plugin with a similar name — manually confirm it applies to the "
                                    "detected version before treating it as confirmed."
                                ),
                                severity=cve["severity"],
                                category="Fingerprint",
                                module="fingerprint",
                                affected_url=url,
                                evidence={"cve": cve["id"], "cvss_score": cve["cvss_score"], "query": keyword},
                                recommendation=f"Review {cve['id']} at the official CVE record and confirm applicability before remediating.",
                                owasp_category="A06:2021 – Vulnerable and Outdated Components",
                                cve=cve["id"],
                                references=[cve["url"]],
                            ))

            # Check exposed generator/version meta tags
            soup = BeautifulSoup(body, "lxml")
            generator = soup.find("meta", attrs={"name": "generator"})
            if generator:
                content = generator.get("content", "")
                findings.append(Finding(
                    title=f"Generator Meta Tag Discloses Technology: {content}",
                    description="The <meta name='generator'> tag reveals CMS/platform version to reconnaissance.",
                    severity=Severity.low,
                    category="Information Disclosure",
                    module="fingerprint",
                    affected_url=url,
                    evidence={"generator": content},
                    recommendation="Remove the generator meta tag from public-facing HTML.",
                    owasp_category="A05:2021 – Security Misconfiguration",
                ))

            # Probe sensitive paths (non-destructive GET)
            base = url.rstrip("/")
            for path in ADMIN_PATHS:
                try:
                    probe = await client.get(f"{base}{path}", follow_redirects=False)
                    if probe.status_code in (200, 403):
                        sev = Severity.high if probe.status_code == 200 else Severity.medium
                        raw["exposed_paths"].append({"path": path, "status": probe.status_code})
                        findings.append(Finding(
                            title=f"Sensitive Path Accessible: {path} (HTTP {probe.status_code})",
                            description=f"Path {path} returned HTTP {probe.status_code}.",
                            severity=sev,
                            category="Information Disclosure",
                            module="fingerprint",
                            affected_url=f"{base}{path}",
                            evidence={"path": path, "status": probe.status_code},
                            recommendation=f"Restrict access to {path} or remove it from production.",
                            owasp_category="A05:2021 – Security Misconfiguration",
                        ))
                except Exception:
                    pass

    except httpx.TimeoutException:
        return ScanResult(module="fingerprint", error=f"Request timed out after {timeout}s")
    except httpx.RequestError as e:
        return ScanResult(module="fingerprint", error=str(e))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="fingerprint", findings=findings, raw_data=raw, duration_ms=duration)
