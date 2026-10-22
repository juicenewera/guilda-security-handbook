# Plano de remediação de segurança

Este plano transforma a auditoria baseada no Guia KipperDev em trabalho executável. A ordem respeita dependências e reduz risco antes de adicionar controles novos.

## Fase 0 — Contenção e autorização

**Responsável:** GSD Security Auditor + operador da infraestrutura

**Prioridade:** crítica · **bloqueia publicação**

- Rotacionar qualquer segredo que apareceu no histórico Git ou em relatórios antigos.
- Confirmar revogação no provedor e revisar acessos ativos.
- Registrar commit, ambiente e escopo de cada teste.

**Aceite:** nenhuma credencial antiga responde; evidência registrada sem expor o valor.

## Fase 1 — Limites de entrada e payload

**Responsável:** GSD App Security

**Prioridade:** alta

- Limitar corpo no Caddy e no runtime antes de `json()`/`formData()`.
- Adotar schemas estritos em projetos, webhooks e uploads.
- Rejeitar campos desconhecidos, `NaN`, infinito, enum inválido e arquivos fora do limite.

**Aceite:** payload grande é recusado antes do parse; casos inválidos não persistem; casos válidos continuam passando.

## Fase 2 — Autorização, RLS e recursos pagos

**Responsável:** GSD Auth/RLS

**Prioridade:** alta

- Criar contas A/B de teste.
- Testar leitura, alteração, exclusão, anexos, aulas, PDFs, transcrições, Gold e RPCs.
- Confirmar RLS/Storage no Supabase real e URLs assinadas com expiração.

**Aceite:** A não acessa B; acesso pago exige entitlement; admin/fundador não ganham privilégios acidentais.

## Fase 3 — SSRF, redirects e abuso

**Responsável:** GSD Production Auditor

**Prioridade:** alta

- Aplicar allowlist de hosts em `join_url`.
- Bloquear redirecionamentos indevidos, loopback, IPv4/IPv6 privados e destinos internos em integrações.
- Configurar limite de requisições por IP e identidade, timeout e tamanho de resposta.
- Adicionar CAPTCHA adaptativo e MFA para administradores.

**Aceite:** destinos fora da allowlist falham; excesso retorna 429; tokens de desafio ausentes, inválidos, expirados ou reutilizados não passam.

## Fase 4 — Logs, Telegram e privacidade

**Responsável:** GSD Privacy/Data + GSD Sentinel

**Prioridade:** alta

- Remover PII, URI completa, username SSH e dados de membros dos alertas.
- Restringir Telegram por `chat_id` e `user_id`; preferir chat privado.
- Criar redaction central para tokens, cookies, Authorization, e-mails e corpos.
- Definir retenção, `logrotate`, limpeza de temporários e política para transcrições/IA.

**Aceite:** nenhum alerta/log contém segredo ou PII desnecessária; retenção e descarte são verificáveis.

## Fase 5 — Infraestrutura e supply chain

**Responsável:** GSD VPS/Infra

**Prioridade:** média/alta

- Fixar imagens Docker por versão e digest.
- Confirmar portas públicas, usuário efetivo, capabilities, volumes, limites e healthchecks.
- Criar baseline de migrations e teste de schema drift.

**Aceite:** release é reproduzível; imagem e schema correspondem ao commit auditado; rollback funciona.

## Fase 6 — Backup e recuperação

**Responsável:** GSD Operations

**Prioridade:** média

- Confirmar backup, retenção e criptografia.
- Restaurar em ambiente descartável.
- Medir RPO/RTO e documentar passos de recuperação.

**Aceite:** restore executado com sucesso e evidência de integridade dos dados.

## Fase 7 — Observabilidade e resposta

**Responsável:** GSD Sentinel/Incident

**Prioridade:** média

- Testar Sentinela, Telegram, Fail2ban, watchdog e uptime externo.
- Simular Redis fora do ar, container unhealthy, sonda HTTP e login SSH suspeito.
- Treinar contenção, rotação, preservação de evidência e rollback.

**Aceite:** cada evento gera alerta deduplicado; existe caminho alternativo se Telegram falhar.

## Fase 8 — Reauditoria e publicação

**Responsável:** GSD Orchestrator

**Prioridade:** obrigatória

- Repetir auditprod no commit corrigido.
- Atualizar matriz de risco com evidência nova, risco residual, responsável e prazo.
- Rodar testes, lint, typecheck, build, secret scan e smoke test.
- Publicar somente relatório sanitizado.

**Aceite:** nenhum item é marcado como resolvido sem reprodução antes e depois.

## Ordem de execução

```text
Fase 0 → Fase 1 → Fase 2 → Fase 3
                         ├→ Fase 4 → Fase 5 → Fase 6
                         └→ Fase 7 → Fase 8
```

As fases 4 e 7 podem avançar em paralelo depois que a contenção estiver concluída. A fase 8 só fecha quando as dependências externas forem comprovadas.
