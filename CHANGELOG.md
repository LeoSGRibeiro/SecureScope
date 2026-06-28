# Changelog

Todas as mudanças notáveis deste projeto são registradas aqui.
Formato baseado em [Keep a Changelog](https://keepachangelog.com/) e [SemVer](https://semver.org/).

## [1.1.0] — 2026-06-27

### Adicionado
- Nova identidade visual inspirada em Linear/Notion/Tailscale (app desktop + frontend): fundo `#151A23`, cards `#202735`, primária turquesa `#2DD4BF`, accent lima `#84CC16`, severidades crítico/médio/baixo (`#F43F5E`/`#FACC15`/`#22C55E`).

### Corrigido
- **Bug crítico de build**: o frontend não tinha `postcss.config.js`, então o Tailwind CSS nunca foi de fato compilado em produção (as diretivas `@tailwind`/`@apply` ficavam literais no CSS final, sem nenhum estilo gerado). Adicionado o arquivo de configuração.
- Dependência `tailwindcss-animate` estava referenciada no `tailwind.config.ts` mas nunca foi instalada — adicionada ao `package.json`.

### Desenvolvido por
Leonardo Ribeiro

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
