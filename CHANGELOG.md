# Changelog

Todas as mudanças notáveis deste projeto são registradas aqui.
Formato baseado em [Keep a Changelog](https://keepachangelog.com/) e [SemVer](https://semver.org/).

## [1.0.0] — 2026-06-27

Versão inicial sob a marca **ThreatLens** (anteriormente SecureScope).

### Adicionado
- Scanners passivos: headers, TLS, cookies, CORS, fingerprint, subdomínios, OWASP, varredura de portas.
- Campo de CVE nos achados (populado quando há um CVE real e inequívoco).
- Tradução PT-BR sob demanda no app desktop (idioma padrão: inglês).
- Exportação de relatórios em CSV e PDF.
- App desktop (PySide6) standalone, sem dependência de Docker/Postgres/Celery.
- Stack completa via Docker Compose (FastAPI + Next.js + Celery + PostgreSQL + Redis + Nginx).
- Rebranding completo de SecureScope para **ThreatLens**, com logo e identidade visual próprios.
- Exibição de versão do produto e autoria em todas as superfícies (API, frontend, app desktop).

### Desenvolvido por
Leonardo Ribeiro
