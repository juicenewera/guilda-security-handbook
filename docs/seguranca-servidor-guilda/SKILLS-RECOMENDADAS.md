# Skills recomendadas para repetir a análise

Skills são roteiros de raciocínio e execução. Elas não substituem revisão humana, testes ou conhecimento do ambiente. Use-as em sequência e registre a evidência de cada etapa.

## Sequência sugerida

| Skill | Quando usar | Resultado esperado |
|---|---|---|
| `security-audit-vibecoders` | Antes de publicar uma API, feature ou mudança de dados | Revisão de IDOR/BOLA, RLS, sessão, DTOs, injeção, segredos, rate limit e infraestrutura |
| `auditprod` | Depois do deploy e em revisões periódicas | Auditoria de produção em 13 camadas, usando probes reais, saúde do serviço, autenticação, RLS, headers, logs, performance, backup e operação |
| `vulnerability-scanner` | Quando existe uma superfície HTTP, dependências ou container para mapear | Lista priorizada de vulnerabilidades reproduzíveis, sem exploração destrutiva |
| `red-team-tactics` | Para simular abuso controlado depois da revisão defensiva | Casos de ataque autorizados, evidência, impacto e correção |
| `vps-sentinel-hardening` | Ao preparar ou endurecer uma VPS | SSH, firewall, Fail2ban, Docker, logs, backups e recuperação |
| `server-management` | Para instalar serviços e operar o host | Mudanças idempotentes, permissões mínimas, rollback e health checks |
| `code-review-checklist` | Em todo pull request sensível | Revisão de qualidade, segurança, tratamento de erros e manutenção |
| `testing-patterns` + `verify-changes` | Antes de merge/deploy | Testes focados, typecheck, lint, smoke test e confirmação do diff real |

> No projeto, `auditprod` é o nome do método/runbook de auditoria de produção (os relatórios ficam em `docs/AUDIT-PROD-*.md`), não uma skill instalada isoladamente. Ao reutilizá-lo em outro sistema, crie um relatório datado, informe o commit/versão auditado e diferencie evidência observada de hipótese.

## Como pensar durante a auditoria

1. **Defina o ativo:** o que pode causar dano se for lido, alterado, apagado ou indisponibilizado?
2. **Defina o ator:** visitante, membro, fundador, admin, worker, operador da VPS ou invasor anônimo.
3. **Defina a fronteira:** browser, API, proxy, container, banco, Storage, Redis, Telegram e host.
4. **Prove a autorização no servidor:** nunca aceite `user_id`, `role`, preço, XP ou caminho de arquivo enviado pelo cliente.
5. **Teste falhas e sucesso:** 401/403/404, sessão expirada, duplicação, replay, timeout, dependência fora do ar e concorrência.
6. **Registre evidência mínima:** rota, horário, status e resultado; não copie segredo ou dado pessoal para o relatório.
7. **Feche com teste de regressão:** transforme cada achado em teste automatizado ou checklist operacional.

### Roteiro do auditprod

1. Identifique exatamente domínio, commit, ambiente e horário da auditoria.
2. Faça probes sem escrita: home, login, rotas protegidas, APIs públicas e `/api/health`.
3. Verifique autenticação, autorização, RLS, Storage, webhooks, headers, TLS, rate limit e exposição de arquivos.
4. Compare aplicação, banco, proxy, container e observabilidade; não confie só no status `200`.
5. Classifique cada achado por severidade, impacto, evidência reproduzível, responsável e prazo.
6. Rode novamente após a correção e registre o que mudou; auditoria antiga nunca deve ser apresentada como estado atual.

## Dados do usuário: regra prática

- **Minimize:** colete apenas o que a funcionalidade precisa; localização pode começar por cidade/bairro opcional, sem exigir endereço preciso.
- **Classifique:** público, membro, privado e secreto. A classificação define quem pode ler, por quanto tempo e onde pode aparecer.
- **Separe identidade de produto:** use IDs internos; não exponha e-mail/telefone em URLs, logs, rankings ou mensagens do bot.
- **Aplique autorização em profundidade:** middleware, handler, query/RPC e RLS devem concordar; a UI nunca é uma barreira.
- **Proteja arquivos:** Storage privado, política por recurso e URL assinada curta; não publique transcrição paga por URL permanente.
- **Proteja logs:** redija tokens, cookies, Authorization, e-mails, telefones, prompts e corpos de requisição; defina retenção e acesso.
- **IA e transcrições:** envie somente o trecho necessário, informe finalidade, restrinja acesso e apague cópias temporárias quando possível.
- **Telegram:** envie contagens e eventos técnicos; nunca senha, token, PII, transcrição ou corpo bruto de log. Restrinja pelo `chat_id`.
- **Retenção e descarte:** documente prazo, backup, restauração e exclusão; apagar da interface não basta se houver cópia em log, Storage ou backup.
- **Incidentes:** preserve evidência sem espalhar dados, revogue credenciais, limite o impacto, comunique os responsáveis e registre a correção.

## Critério de pronto

Uma mudança só está pronta quando há: ameaça identificada, autorização provada no servidor, dado minimizado, erro seguro, logs sem segredo, teste de abuso, teste normal, rollback e operador responsável.
