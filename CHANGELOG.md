# Changelog

Todas as mudanças notáveis deste projeto são registradas aqui.
Formato baseado em [Keep a Changelog](https://keepachangelog.com/) e [SemVer](https://semver.org/).

## [1.4.1] — 2026-06-28

### Corrigido
- Relatório (PDF/CSV) do app desktop agora exibe a data/hora em que o scan foi efetuado.
- Coluna "Severidade" do PDF estava sem quebra de texto e estourava visualmente para a coluna seguinte (ex: "INFORMATIONAL") — agora usa `Paragraph` com largura ajustada, igual às demais colunas.

### Desenvolvido por
Leonardo Ribeiro

## [1.4.0] — 2026-06-28

### Adicionado
- Mais de 15 novas assinaturas de detecção no `fingerprint_scanner`: Tailwind CSS, Google Tag Manager, Google Analytics, Google reCAPTCHA, Hotjar, Webflow, Wix, Squarespace, Shopify, WooCommerce, Magento, PHP, ASP.NET, Svelte, Alpine.js, jQuery UI, Font Awesome, Vercel, Netlify.
- A busca de CVE agora roda para **qualquer tecnologia elegível detectada** (não só jQuery/Bootstrap desatualizados), limitada a 3 consultas por scan para respeitar o limite de requisições do NVD. Tecnologias de infraestrutura/CDN (Nginx, Apache, IIS, Cloudflare, CloudFront, Vercel, Netlify) ficam de fora da busca de CVE por gerarem ruído, não sinal.

### Validado
- Testado contra um site real (https://aplicap.com.br) com WordPress + PHP detectados: retornou `CVE-1999-0238` (crítico) para PHP, com o campo `cve` populado corretamente.

### Desenvolvido por
Leonardo Ribeiro

## [1.3.0] — 2026-06-28

### Adicionado
- Consulta em tempo real à lista oficial de CVEs ([cve.org](https://www.cve.org/)), via a API pública do NVD (que enriquece os mesmos dados do CVE List), para bibliotecas desatualizadas detectadas pelo `fingerprint_scanner`. Cada CVE encontrado popula o campo `cve` do achado e linka de volta para o registro oficial em `cve.org/CVERecord`.
- Novo módulo `backend/app/services/scanners/cve_lookup.py`, reaproveitável por outros scanners.
- Achados de CVE por palavra-chave usam linguagem explícita de "verificar aplicabilidade", já que a busca por nome de produto pode retornar CVEs de plugins/bibliotecas com nome semelhante, não necessariamente da versão exata detectada.

### Desenvolvido por
Leonardo Ribeiro

## [1.2.0] — 2026-06-27

### Adicionado
- Alternância de tema claro/escuro com ícone (sol/lua), no app desktop e no frontend.
- Frontend: tema claro completo (CSS vars espelhadas do tema escuro), conectado via `next-themes` (já estava instalado, mas nunca tinha sido configurado — `ThemeProvider` adicionado em `providers.tsx`, preferência persistida em `localStorage`).
- App desktop: `DARK_STYLESHEET`/`LIGHT_STYLESHEET` alternáveis via botão no cabeçalho.

### Desenvolvido por
Leonardo Ribeiro

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
