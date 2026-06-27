# ThreatLens — Enxergando ameaças antes que elas virem incidentes

> **AUTHORIZED USE ONLY.** This tool is exclusively for security testing of systems you own
> or have **explicit written authorization** to test. Unauthorized use is illegal and may
> violate applicable laws (CFAA, GDPR, LGPD, etc.).

---

## Overview

ThreatLens is a production-grade, full-stack web security analysis platform focused on
**defensive, non-destructive auditing**. It helps security teams identify misconfigurations,
validate hardening, and generate professional reports.

### What it does (defensively)

| Module | Analysis |
|--------|----------|
| **HTTP Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **TLS/SSL** | Certificate validity/expiry, protocol version, cipher strength, hostname match |
| **Cookies** | HttpOnly, Secure, SameSite, expiry analysis |
| **CORS** | Wildcard origins, reflected origins, credential exposure, dangerous methods |
| **Fingerprint** | CMS, frameworks, server software, CDN/WAF, exposed admin paths |
| **Subdomains** | Certificate transparency, passive DNS, subdomain takeover indicators |
| **OWASP Top 10** | Error disclosure, mixed content, directory listing, sensitive file exposure, CSRF indicators |

---

## Architecture

```
securescope/
├── backend/                 # Python FastAPI
│   ├── app/
│   │   ├── api/v1/         # REST endpoints (auth, targets, scans)
│   │   ├── core/           # Config, DB, security utils
│   │   ├── models/         # SQLAlchemy ORM (User, Target, Scan, Vulnerability)
│   │   ├── schemas/        # Pydantic request/response schemas
│   │   ├── services/
│   │   │   └── scanners/   # Modular scanner engine
│   │   │       ├── base.py            # Finding dataclass, risk scoring
│   │   │       ├── headers_scanner.py
│   │   │       ├── tls_scanner.py
│   │   │       ├── cookies_scanner.py
│   │   │       ├── cors_scanner.py
│   │   │       ├── fingerprint_scanner.py
│   │   │       ├── subdomains_scanner.py
│   │   │       ├── owasp_scanner.py
│   │   │       └── orchestrator.py    # Async parallel runner
│   │   └── workers/        # Celery task queue
│   └── alembic/            # DB migrations
├── frontend/               # Next.js 14 + TypeScript
│   └── src/
│       ├── app/            # Next.js App Router
│       ├── components/     # UI components
│       ├── lib/            # API client, utilities
│       ├── store/          # Zustand state management
│       └── types/          # TypeScript types
├── nginx/                  # Reverse proxy config
├── scripts/                # Setup automation
└── docker-compose.yml
```

---

## Quick Start

### Prerequisites
- Docker + Docker Compose
- (Optional) Node.js 20+ and Python 3.12+ for local dev

### Docker (recommended)

**Linux/macOS:**
```bash
cd securescope
chmod +x scripts/setup.sh
./scripts/setup.sh
```

**Windows (PowerShell):**
```powershell
cd securescope
.\scripts\setup.ps1
```

The script will:
1. Generate a secure `SECRET_KEY` in `.env`
2. Build all Docker images
3. Run database migrations
4. Start all services

**URLs after startup:**
- Frontend: http://localhost:3000
- API Docs (Swagger): http://localhost:8000/api/docs
- Task monitor (Flower): http://localhost:5555

### Create First User

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","username":"admin","password":"Secure123!"}'
```

---

## Local Development

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp ../.env.example .env            # Edit DATABASE_URL / REDIS_URL
alembic upgrade head
uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
# Create .env.local
echo "NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1" > .env.local
npm run dev
```

### Celery Worker

```bash
cd backend
celery -A app.workers.celery_app worker --loglevel=info
```

---

## User Flow

1. **Register** — create account
2. **Accept Ethics Agreement** — mandatory acknowledgment of authorized use
3. **Add Target** — confirm written authorization for the target
4. **Run Scan** — select modules or run full scan (async via Celery)
5. **View Findings** — sorted by severity with evidence and recommendations
6. **Mark False Positives** — refine results
7. **Export Report** — PDF/JSON (coming soon)

---

## Security of the Platform Itself

- JWT authentication with short-lived access tokens
- RBAC (Admin / Analyst / Viewer)
- Anti-SSRF validation on all target inputs (RFC-1918 block, loopback block, cloud metadata block)
- Rate limiting on all endpoints (Nginx + slowapi)
- Input sanitization via Pydantic validators
- CSP, HSTS, and secure headers on the frontend (Next.js)
- Audit logging of all user actions
- Ethics acceptance enforced at both registration and login

---

## Ethical Use Policy

This platform enforces responsible use through:

- **Mandatory ethics acceptance** checkbox before every login
- **Authorization confirmation** required for every target
- **Audit trail** of all scans and actions (stored 365 days)
- **Scope controls** — internal/private IPs blocked as targets
- No modules perform active exploitation, brute force, DoS, or payload injection

---

## Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 14, TypeScript, TailwindCSS, shadcn/ui, Framer Motion, Recharts |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2.0 (async) |
| Queue | Celery + Redis |
| Database | PostgreSQL 16 |
| Proxy | Nginx |
| Containers | Docker + Docker Compose |

---

## License

For authorized security research and testing only. Not for offensive or unauthorized use.
