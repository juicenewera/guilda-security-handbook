# Auditoria de segurança baseada no Guia KipperDev

**Data:** 2026-10-22

**Escopo:** repositório local da Guilda, operação documentada e evidências disponíveis no código.

**Fonte:** [KipperDev - Guia Segurança Vibe Coding](https://drive.google.com/file/d/1Sv9C1SHkSKQX6zAMwUvrqUe7S9nY-T59/view?usp=drivesdk)

**Método:** leitura do guia, auditoria local read-only, revisão dos relatórios `auditprod` e análise paralela por três agentes GSD.

> Este relatório não é certificação e não prova que a produção está segura. O estado do Supabase, GitHub Actions, firewall, backups, containers em execução e credenciais precisa ser confirmado no ambiente autorizado.

## Resultado executivo

### Bloqueadores

1. **Segredos históricos no Git (crítico):** o blob `.env.local` ainda existe no histórico (`5ab92b5:.env.local`), conforme confirmado por `git cat-file` e relatórios anteriores. Mesmo que os valores tenham sido removidos dos arquivos atuais, precisam ser revogados no provedor e o histórico deve ser tratado com procedimento coordenado.
2. **Payload sem limite antes do parse (alto):** várias rotas chamam `request.json()` ou `request.formData()` antes de aplicar limite de tamanho/rate limit. Isso permite consumo de memória/CPU antes da validação.

### Riscos altos

- `event-join/[id]` aceita URL `https://` armazenada e pode funcionar como open redirect/phishing sem allowlist de hosts.
- Validação de entrada incompleta em `projects/[id]` e no webhook Hyper (`any`, campos extras e números não finitos).
- CAPTCHA/MFA para login e cadastro não foram encontrados no código; rate limit e honeypot não substituem desafio adaptativo.
- Logs podem conter PII ou resposta de provedor: `sync-profile`, webhook Hyper e Mayara precisam de redaction e retenção definida.
- Sentinela envia IP completo, URI, usuário SSH, admins e usernames ao Telegram; o `chat_id` sozinho não restringe membros de um grupo.

### Controles positivos confirmados

- service role não aparece em componentes client;
- autorização server-side existe nas principais rotas sensíveis;
- RLS/Storage, URLs assinadas e entitlement são usados para recursos privados;
- Redis possui fallback para Postgres/local e timeout;
- Docker usa usuário não-root, capabilities removidas, healthcheck e limites;
- Caddy aplica TLS, HSTS, CSP, `X-Frame-Options`, `nosniff`, Referrer-Policy e logs JSON;
- deploy mantém release anterior, lock, healthcheck e rollback;
- webhook Hyper usa token obrigatório, comparação em tempo constante, rate limit e idempotência;
- Sentinela possui testes de classificação, cooldown, SSH, uso e comandos.

## Matriz dos 12 riscos do guia

| Risco | Estado | Evidência local | Próxima ação |
|---|---|---|---|
| Segredos no frontend/histórico | **Crítico** | Histórico `.env.local`; atuais clients não importam service role | Rotacionar chaves, confirmar revogação e limpar histórico com plano de preservação |
| Entradas sem validação | **Alto** | `app/api/projects/[id]/route.ts`, webhook Hyper usam `any`/campos permissivos | Schemas estritos, enums, limites e números finitos |
| SQL injection | Não confirmado | Filtros PostgREST parametrizados; RPC/SQL manual ainda exige revisão | Testes em banco descartável e auditoria de funções/RPC |
| Prompt injection | **Residual médio/alto** | Mayara trata conteúdo como não confiável, mas heurística não autoriza ferramentas | Allowlist de ferramentas, sessão, escopo e confirmação fora do modelo |
| XSS | **Médio** | JSON-LD em blog usa `JSON.stringify` diretamente; outros pontos usam helper seguro | Helper único com escape `<`, `>` e `&`; revisar URLs e Markdown |
| IDOR/BOLA | **Residual médio** | Ownership checks em projetos, recursos e eventos; RLS final não foi provada aqui | Teste A contra B em leitura, edição, exclusão, anexos e RPC |
| SSRF/open redirect | **Alto** | Geocoder roda no browser; `event-join` aceita destino HTTPS armazenado | Allowlist Discord/WhatsApp, bloqueio de redirecionamento e timeouts |
| Senhas em texto puro | **Residual médio** | Auth delegado ao Supabase; scripts podem receber senha por env/CLI | Remover senha de argumentos/logs e revisar dumps/migrações |
| DoS/DDoS | **Alto** | Rate limit existe, mas parse ocorre antes do limite em várias rotas | Limite no Caddy/runtime, abort de stream, custos e timeout menores |
| Enumeração/admin | Baixo residual | Proxy e handlers exigem admin; diretório mascara contatos | Inventário e matriz anônimo/membro/fundador/admin |
| Bots login/cadastro | **Médio/alto** | Não há Turnstile/reCAPTCHA/MFA evidenciado | Limites por IP/conta, desafio adaptativo e MFA para admins |
| Erros que vazam dados | **Médio** | `errorId` e mensagens genéricas são bons; logs ainda têm PII/corpos | Redaction central, requestId, retenção e testes 4xx/5xx |

## Plano por etapas e responsáveis GSD

### Etapa 0 — Contenção e inventário (responsável: GSD Security Auditor)

- Revogar/rotacionar qualquer segredo que apareceu no histórico ou relatório anterior.
- Registrar commit, domínio, ambiente, horário e escopo da auditoria.
- Classificar achados como confirmado, suspeito ou não verificável.

**Aceite:** nenhuma chave antiga responde; inventário de segredos e responsáveis existe; nenhum segredo novo é impresso no relatório.

### Etapa 1 — Aplicação e entradas (responsável: GSD App Security)

- Aplicar schemas estritos a projetos, webhooks e uploads.
- Rejeitar campos desconhecidos, categorias inválidas e `NaN`/infinito.
- Adicionar testes positivos e negativos para cada rota.

**Aceite:** payload inválido retorna 400 sem persistência; payload válido continua funcionando; testes reproduzem a falha antes e passam depois.

### Etapa 2 — Autorização, RLS e recursos (responsável: GSD Auth/RLS)

- Criar contas A/B de teste e validar leitura, edição, exclusão, anexos, cursos, transcrições e Gold.
- Confirmar RLS e Storage no projeto Supabase real.
- Revisar RPCs `SECURITY DEFINER`, `search_path` e grants.

**Aceite:** A nunca acessa B; admin e fundador mantêm apenas os privilégios previstos; URLs privadas expiram e não funcionam sem entitlement.

### Etapa 3 — Borda e abuso (responsável: GSD Production Auditor)

- Limitar tamanho de body no Caddy/runtime antes do parse.
- Corrigir allowlist de `join_url`, timeouts e destinos externos.
- Validar rate limit por IP/conta, proxy confiável, CAPTCHA adaptativo e MFA de admin.

**Aceite:** payload grande é recusado antes de consumir memória; URL fora da allowlist falha; excesso retorna 429; token de desafio ausente/inválido não cria conta.

### Etapa 4 — Dados, logs e IA (responsável: GSD Privacy/Data)

- Remover PII desnecessária dos logs e do Telegram; manter detalhes forenses apenas localmente.
- Restringir Sentinela por `chat_id` e `user_id`; preferir chat privado.
- Definir retenção, `logrotate`, limpeza de temporários de transcrição e uso de subprocessadores/IA.
- Confirmar consentimento e visibilidade de avatares, banners, localização, contatos e transcrições.

**Aceite:** logs e alertas não contêm token, senha, cookie, URI completa ou PII desnecessária; política de retenção e exclusão está escrita e testada.

### Etapa 5 — Infraestrutura, supply chain e recuperação (responsável: GSD VPS/Infra)

- Fixar imagens Docker por versão/digest, especialmente Ollama.
- Confirmar portas públicas, capabilities, volumes, limites e healthchecks na VPS.
- Criar baseline de migrations/schema drift.
- Confirmar backup, retenção e restore em ambiente descartável; medir RPO/RTO.

**Aceite:** restore reproduzível documentado; imagem e schema auditados correspondem ao commit publicado; serviço volta após falha controlada.

### Etapa 6 — Observabilidade e incidente (responsável: GSD Sentinel/Incident)

- Testar Telegram, Sentinela, Fail2ban, watchdog e alerta externo de uptime.
- Simular container indisponível, login SSH suspeito, sonda HTTP e falha do Redis.
- Documentar contenção, rotação, comunicação, preservação de evidência e rollback.

**Aceite:** cada simulação gera alerta único, sem PII excessiva, e existe caminho alternativo quando Telegram falha.

### Etapa 7 — Reauditoria auditprod (responsável: GSD Orchestrator)

- Repetir probes HTTP, auth/RLS, Storage, headers, TLS, rate limit, Docker, logs e backup no commit corrigido.
- Atualizar a matriz com evidência nova, risco residual, responsável e prazo.
- Publicar somente o relatório sanitizado.

**Aceite:** nenhum item é marcado como resolvido sem teste reproduzível e evidência do ambiente correspondente.

## O que foi verificado nesta rodada

- PDF do Drive baixado e extraído: 15 páginas, 12 riscos e checklist geral.
- Código e documentação local revisados em modo somente leitura.
- Três análises GSD paralelas: aplicação, produção/infraestrutura e privacidade/dados.
- `python -m unittest ops/sentinela/test_sentinela.py`: **14/14 passando**.
- Nenhum deploy, escrita no Supabase, carga em produção ou alteração de dados foi executado.

## Dependências externas não confirmadas

Estado real de RLS/Storage/Supabase, secrets do GitHub, firewall/Fail2ban, containers em execução, backups/restore, CAPTCHA/MFA, envio real do Telegram, WAF/DDoS, uptime externo e rotação efetiva de credenciais.

## Regra de publicação

O PDF original permanece apenas como fonte externa. Este relatório não copia credenciais, PII, IPs reais, tokens ou logs brutos. O próximo ciclo deve atualizar a data e o commit auditado, em vez de reutilizar este resultado como se fosse estado atual.
