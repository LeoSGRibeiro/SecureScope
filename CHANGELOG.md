# Changelog

## [2.0.0] — 2026-07-08

### Adicionado
- **Scan Semanal Automático (Fase 5)**: novo sistema de agendamento de scans recorrentes rodando no backend Docker via Celery Beat. Permite cadastrar URLs para varredura automática a cada N dias (padrão: 7), compara o resultado com o scan anterior do mesmo alvo, e envia por e-mail apenas o **delta** — novas vulnerabilidades encontradas e vulnerabilidades resolvidas desde a última análise. O e-mail inclui tabelas coloridas por severidade das findings novas e resolvidas, além do risk score atual.
- **Janela de agendamentos no app desktop**: novo botão "⏰ Agendamentos" abre uma janela de gerenciamento onde é possível adicionar URLs com e-mail de destino e intervalo configurável, ativar/pausar e remover agendamentos existentes, e visualizar próximo scan e último scan executado. Autenticação via JWT (credenciais de acesso à plataforma).
- **Envio de e-mail via SMTP/Gmail**: `email_service.py` usa `smtplib` (stdlib, sem nova dependência) com STARTTLS na porta 587. Configurado via variáveis de ambiente `SMTP_USER`, `SMTP_PASS` (senha de app Google de 16 chars), `EMAILS_FROM`.
- **Novos endpoints REST**: `POST/GET /api/v1/scheduled-scans`, `PATCH /api/v1/scheduled-scans/{id}` (ativar/pausar), `DELETE /api/v1/scheduled-scans/{id}`.
- **Serviço `beat` no Docker Compose**: Celery Beat roda como serviço separado, verificando a cada hora quais scans estão vencidos e despachando tasks para o worker existente.
- **Tabela `scheduled_scans`**: nova tabela PostgreSQL com migration Alembic (`a3c5f8d2e901`), armazenando URL, módulos, e-mail, intervalo, status ativo/inativo, `last_run_at` e `next_run_at`.
- **Enumeração de ameaças no CSV**: coluna `num_ameaca` (número sequencial) e novas colunas `data_conclusao` (prazo calculado por severidade), `status` e `observacao` no export CSV para controle de tratamento.
- **Coluna `#` no PDF técnico**: o relatório PDF existente ganhou uma coluna numérica de controle para facilitar referência cruzada com o CSV exportado.
- **Correção de export PDF**: caracteres especiais HTML (`&`, `<`, `>`) em campos de findings agora são escapados antes de passar ao ReportLab, eliminando o erro "paraparser: syntax error: parse ended with 1 unclosed tags para".

### Desenvolvido por
Leonardo Ribeiro

## [1.9.0] — 2026-07-02

### Adicionado
- **Relatório Gerencial PDF**: novo botão "📋 Rel. Gerencial" no app desktop exporta um relatório orientado a gestores/clientes, com: capa com Risk Score e interpretação textual (Baixo/Moderado/Elevado/Crítico), sumário executivo em linguagem de negócio, perfil de infraestrutura e tecnologia (com versões e status de atualização), distribuição de riscos por severidade com barras visuais proporcionais, plano de ação detalhado com prioridade e prazo sugerido calculado a partir da data do scan por severidade (Imediata ≤ 7d / Alta ≤ 30d / Média ≤ 90d / Baixa ≤ 180d), seção de observações para achados informativos, e apêndice técnico com CVE/OWASP/CVSS para referência de TI. Rodapé com número de página em todas as páginas.
- O relatório existente ("Exportar PDF") permanece intacto — os dois convivem e servem públicos diferentes.
- O arquivo exportado recebe sufixo `_gerencial` no nome (ex: `www.site.com_20260702_1430_gerencial.pdf`).

### Desenvolvido por
Leonardo Ribeiro

Todas as mudanças notáveis deste projeto são registradas aqui.
Formato baseado em [Keep a Changelog](https://keepachangelog.com/) e [SemVer](https://semver.org/).

## [1.8.0] — 2026-06-30

### Adicionado
- A recomendação da finding "Infrastructure & Technology Profile" agora lista, para cada ferramenta com versão identificada (PHP, Nginx, Apache, Apache Tomcat, WordPress, jQuery), a versão detectada e a mais atual disponível: "atualize de X para Y" quando desatualizada, "já está na versão mais recente" quando atualizada, ou um aviso explícito quando não há fonte confiável de comparação (ex: jQuery/Bootstrap, bibliotecas JS sem um "latest" oficial único) — nunca inventa uma versão "mais recente" sem fonte.
- Extração de versão também para **jQuery** e **Bootstrap** (a partir do nome do arquivo no HTML).
- `version_check.py` ganhou `get_comparison()`, função única reaproveitada tanto para as findings individuais "Outdated X" quanto para a recomendação consolidada — evita consultar o endoflife.date duas vezes pela mesma tecnologia.

### Desenvolvido por
Leonardo Ribeiro

## [1.7.1] — 2026-06-30

### Alterado
- A finding "Infrastructure & Technology Profile" deixou de aparecer como uma linha dentro da tabela de achados (no app desktop e no PDF exportado) e passou a ser exibida como um bloco descritivo no cabeçalho do relatório/tela, junto com Alvo/Data-Hora/Risk score — já que é um resumo informativo, não um "achado" individual.

### Desenvolvido por
Leonardo Ribeiro

## [1.7.0] — 2026-06-30

### Adicionado
- Nova finding consolidada **"Infrastructure & Technology Profile"** no `fingerprint_scanner`, reunindo num único lugar: linguagem/plataforma de backend (PHP, Java, Node.js/Express, ASP.NET, .NET Core/Kestrel, Ruby on Rails, Django, Laravel), CMS (WordPress, Drupal, Joomla, Magento, Shopify, etc.), servidor web com versão (Nginx, Apache, Apache Tomcat, IIS) e hospedagem/CDN (Cloudflare, AWS CloudFront, AWS S3/ELB, Azure, Google Cloud, Akamai, Fastly, Vercel, Netlify).
- Detecção de **Java** (JSP/JSESSIONID/JSF) e **Apache Tomcat** (com comparação de versão via endoflife.date).
- Novo módulo `hosting_lookup.py`: quando nenhum header de CDN/cloud é detectado, resolve o IP do alvo e consulta o `ipinfo.io` para identificar a organização/ASN dona do IP (ex: "AS16509 Amazon.com, Inc."), servindo de fallback para descobrir onde o site está hospedado.

### Corrigido
- Detecção de **PHP** tinha falso-positivo: qualquer site com o header `X-Powered-By` (independente do valor — ex: "Express", "ASP.NET") era classificado como PHP, pois a checagem só via se o header existia, não o conteúdo. Agora exige que o valor do header contenha literalmente "PHP".
- Detecção de **Ruby on Rails** também tinha sinal genérico demais (`x-request-id`, presente em muitos frameworks não-Rails) — removido, mantendo só `x-runtime`.

### Desenvolvido por
Leonardo Ribeiro

## [1.6.1] — 2026-06-30

### Corrigido
- Risk Score sempre vinha **0** em scans com alguns achados médios/altos/críticos: a fórmula antiga (`100 - peso_total * 0.8`) era linear e saturava em zero rapidamente — por exemplo, só 2 achados críticos (peso 100 cada) já eram suficientes para zerar a nota. Trocada por uma curva de retorno decrescente (`100 / (1 + peso_total / 50)`), que dá uma nota proporcional à gravidade real em vez de colapsar para 0 em qualquer scan com achados não-triviais (ex: 1 crítico isolado agora resulta em ~33, não 0).

### Desenvolvido por
Leonardo Ribeiro

## [1.6.0] — 2026-06-30

### Adicionado
- `fingerprint_scanner` agora extrai a **versão exata** de PHP, Nginx, Apache e WordPress (via headers `Server`/`X-Powered-By` e a tag `<meta name="generator">`) e compara com a última versão estável de cada uma via a API pública do endoflife.date, gerando uma finding "Outdated X Version Detected" quando desatualizado, com severidade escalada por quão atrás está (major desatualizado → alta, minor → média, patch → baixa). IIS continua só com detecção (sem comparação, por falta de fonte pública confiável de "última versão").
- Novo módulo `backend/app/services/scanners/version_check.py` e dependência `packaging==24.0`.
- Traduções PT-BR para os novos achados de versão desatualizada.

### Desenvolvido por
Leonardo Ribeiro

## [1.5.0] — 2026-06-29

### Adicionado
- **Módulos de análise intrusiva** (opt-in, requerem confirmação extra): `sqli_xss` (injeção SQL/XSS ativa com payloads reais), `dirbuster` (wordlist de ~200 caminhos sensíveis), `auth_bruteforce` (brute-force controlado de login com 12 credenciais comuns, throttle de 2s, para no primeiro sucesso), `port_scan_deep` (varredura de ~100 portas com banner grabbing).
- Novo campo `Target.intrusive_testing_confirmed` — a API retorna `403` se um scan solicitar módulos intrusivos sem essa confirmação explícita no Target, independente do `authorization_confirmed` já existente.
- App desktop: seletor de **modo de scan** (Padrão/Profundo) — modo "Padrão" roda só os 8 módulos passivos (como antes); modo "Profundo" libera os módulos intrusivos (desmarcados por padrão) e exige que o usuário digite "EU ENTENDO OS RISCOS" antes de iniciar um scan com qualquer módulo intrusivo selecionado.
- Traduções PT-BR para os achados dos 4 novos módulos.

### Desenvolvido por
Leonardo Ribeiro

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
