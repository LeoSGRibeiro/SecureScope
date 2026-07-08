"""
Directory/File Brute-Force Scanner (INTRUSIVE)
Probes a much larger wordlist of common sensitive paths than the small
fixed lists in fingerprint_scanner.py/owasp_scanner.py. Non-destructive
(GET requests only), but generates significantly more requests than the
passive scanners and may trip rate-limiting/WAF rules on the target.
"""
import asyncio
import time
import httpx
from app.services.scanners.base import Finding, ScanResult, Severity

# ~200 entries across common categories. GET-only probes, no payloads.
WORDLIST = [
    # Admin panels / CMS
    "/admin", "/admin/", "/admin.php", "/administrator/", "/administrator.php",
    "/wp-admin/", "/wp-login.php", "/wp-config.php", "/wp-content/", "/wp-includes/",
    "/manager/", "/manager/html", "/cpanel", "/phpmyadmin/", "/pma/",
    "/joomla/administrator/", "/typo3/", "/umbraco/", "/craft/admin",
    "/_admin/", "/adminpanel/", "/admincp/", "/moderator/",
    # Backups / archives
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql", "/backups/",
    "/db.sql", "/db.sqlite3", "/dump.sql", "/database.sql", "/site.zip",
    "/www.zip", "/old/", "/old.zip", "/backup.bak", "/site.tar",
    # VCS / secrets
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.hg/", "/.bzr/",
    "/.aws/credentials", "/.ssh/id_rsa", "/.ssh/authorized_keys", "/.env",
    "/.env.local", "/.env.production", "/.npmrc", "/.dockerignore",
    "/.htpasswd", "/.htaccess", "/secrets.yml", "/credentials.json",
    "/id_rsa", "/id_rsa.pub", "/.netrc", "/.pgpass",
    # Config files
    "/config.php", "/configuration.php", "/settings.py", "/web.config",
    "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
    "/Gemfile", "/Gemfile.lock", "/requirements.txt", "/Pipfile",
    "/app.config", "/appsettings.json", "/local.settings.json",
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    "/.dockerenv", "/nginx.conf", "/httpd.conf", "/php.ini",
    # CI/CD
    "/Jenkinsfile", "/.circleci/config.yml", "/.github/workflows/",
    "/.gitlab-ci.yml", "/.travis.yml", "/azure-pipelines.yml", "/bitbucket-pipelines.yml",
    # IDE / editor leftovers
    "/.idea/workspace.xml", "/.vscode/settings.json", "/.DS_Store",
    "/Thumbs.db", "/.vimrc", "/.bash_history", "/.zsh_history",
    # APIs / docs
    "/api/", "/api/v1/", "/api/v1/users", "/api/v1/swagger.json",
    "/api/swagger.json", "/swagger.json", "/swagger-ui.html", "/openapi.json",
    "/graphql", "/graphiql", "/api-docs/", "/api/docs", "/redoc",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    # Cloud / containers
    "/actuator/health", "/actuator/env", "/actuator/", "/health", "/healthz",
    "/metrics", "/debug/pprof/", "/server-status", "/server-info",
    "/.kube/config", "/k8s/", "/terraform.tfstate", "/terraform.tfvars",
    # Logs / debug
    "/error_log", "/error.log", "/debug.log", "/access.log", "/app.log",
    "/logs/", "/log/", "/storage/logs/", "/tmp/", "/var/log/",
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    # Uploads / misc
    "/uploads/", "/upload/", "/files/", "/media/", "/static/admin/",
    "/install/", "/install.php", "/setup.php", "/setup/",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/humans.txt",
    "/elmah.axd", "/trace.axd", "/web.config.bak", "/global.asax",
    # Common app frameworks
    "/laravel/.env", "/storage/framework/", "/vendor/", "/vendor/autoload.php",
    "/node_modules/", "/.next/", "/__pycache__/", "/venv/", "/.venv/",
    "/django.log", "/manage.py", "/wsgi.py", "/asgi.py",
    # Auth / session leftovers
    "/login", "/login.php", "/login.aspx", "/signin", "/auth/login",
    "/oauth/token", "/.well-known/jwks.json", "/session.php",
    # Misc sensitive
    "/.well-known/", "/server.key", "/server.crt", "/private.key",
    "/cert.pem", "/keystore.jks", "/.npm/", "/.cache/", "/.config/",
    "/README.md", "/CHANGELOG.md", "/TODO.md", "/.editorconfig",
    "/yarn.lock", "/pnpm-lock.yaml", "/Pipfile.lock", "/poetry.lock",
    "/Makefile", "/Vagrantfile", "/ansible.cfg", "/inventory.ini",
]

# Low-sensitivity entries — still informative, but not worth "high" severity.
LOW_SENSITIVITY = {"/robots.txt", "/sitemap.xml", "/humans.txt", "/.well-known/security.txt", "/README.md", "/CHANGELOG.md"}

MAX_CONCURRENCY = 15
REQUEST_TIMEOUT = 8


async def _probe(client: httpx.AsyncClient, base: str, path: str, semaphore: asyncio.Semaphore) -> dict | None:
    async with semaphore:
        try:
            resp = await client.get(f"{base}{path}", follow_redirects=False, timeout=REQUEST_TIMEOUT)
            if resp.status_code in (200, 403):
                return {"path": path, "status": resp.status_code}
        except Exception:
            pass
    return None


async def scan(url: str, timeout: int = 60) -> ScanResult:
    start = time.monotonic()
    findings: list[Finding] = []
    raw: dict = {"wordlist_size": len(WORDLIST), "hits": []}

    base = url.rstrip("/")

    try:
        async with httpx.AsyncClient(
            verify=False,
            headers={"User-Agent": "ThreatLens-Scanner/1.0 (Authorized Security Audit)"},
        ) as client:
            semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
            results = await asyncio.wait_for(
                asyncio.gather(*[_probe(client, base, path, semaphore) for path in WORDLIST]),
                timeout=timeout,
            )
    except asyncio.TimeoutError:
        return ScanResult(module="dirbuster", error="Directory brute-force timed out")
    except Exception as e:
        return ScanResult(module="dirbuster", error=str(e))

    hits = [r for r in results if r is not None]
    raw["hits"] = hits

    for hit in hits:
        path = hit["path"]
        status = hit["status"]
        if status == 200:
            severity = Severity.medium if path in LOW_SENSITIVITY else Severity.high
        else:
            severity = Severity.low

        findings.append(Finding(
            title=f"Exposed Path: {path} (HTTP {status})",
            description=f"Path '{path}' returned HTTP {status}, indicating it exists on the server.",
            severity=severity,
            category="Information Disclosure",
            module="dirbuster",
            affected_url=f"{base}{path}",
            evidence={"path": path, "status": status},
            recommendation=f"Restrict or remove access to '{path}' if not required in production.",
            owasp_category="A05:2021 – Security Misconfiguration",
        ))

    if not findings:
        findings.append(Finding(
            title="No Exposed Paths Found",
            description=f"None of the {len(WORDLIST)} probed paths were accessible.",
            severity=Severity.informational,
            category="Information Disclosure",
            module="dirbuster",
            affected_url=url,
        ))

    duration = int((time.monotonic() - start) * 1000)
    return ScanResult(module="dirbuster", findings=findings, raw_data=raw, duration_ms=duration)
