---
name: security-audit-vibecoders
description: Audita a segurança de um projeto de software (SaaS, API, app web) construído com auxílio de IA ("vibe coding"), procurando as falhas mais comuns que assistentes de IA costumam deixar passar — IDOR/BOLA, RLS ausente no Supabase/Postgres, sessão insegura (JWT em localStorage), exposição de dados sem DTO, confiança indevida em valores vindos do client (preço/quantidade), segredos versionados no Git, ausência de rate limiting e portas de servidor mal configuradas. Use esta skill sempre que o usuário pedir uma "auditoria de segurança", "revisão de segurança", "análise de vulnerabilidades", "checklist de produção", "isso está seguro para produção?", ou qualquer variação de "meu projeto/SaaS/API está seguro". Também dispare esta skill proativamente antes de qualquer deploy em produção, ou quando o usuário mencionar LGPD, dados de usuários, pagamentos/checkout, autenticação, ou tabelas do Supabase.
---

# Auditor de Segurança para Vibe Coders (Método VCS)

Esta skill implementa a Etapa 3 do Método VCS ("Agente Auditor" / Slop Fix): uma varredura ofensiva no código de um projeto, procurando ativamente pelas vulnerabilidades mais comuns introduzidas por código gerado por IA, antes que alguém de fora as encontre primeiro.

## Como conduzir a auditoria

1. **Mapeie o projeto primeiro.** Rode uma varredura da estrutura de pastas (rotas de API, models/schemas de banco, middlewares de auth, componentes de checkout/pagamento, arquivos `.env*`). Não pule direto para grep — entenda a stack (Next.js? Express? Supabase? Stripe?) antes de aplicar os padrões abaixo.

2. **Para cada categoria abaixo, procure ativamente no código** (não presuma — leia os arquivos relevantes). Use `grep`/busca por padrões como ponto de partida, mas sempre confirme lendo o trecho de código real antes de reportar um achado.

3. **Classifique cada achado** por severidade:
   - 🔥 **Crítico** — exploração trivial, dado sensível ou dinheiro em risco direto.
   - ⚠️ **Alto** — exploração requer algum esforço, mas o impacto é sério.
   - 🔎 **Atenção** — boa prática ausente, risco indireto ou baixa probabilidade.

4. **Para cada achado, entregue:** arquivo + linha, o que está errado, como seria explorado, e o código corrigido pronto para colar (não apenas a explicação).

5. **Termine com um checklist de pré-deploy** (✅/❌ por item) e um resumo de prioridade (o que corrigir primeiro).

## As 8 categorias a verificar

### 1. IDOR / BOLA (Broken Object Level Authorization)
Procure rotas que recebem um `id`/`invoiceId`/`userId` na URL ou no corpo e buscam o registro **sem** verificar se pertence ao usuário autenticado.
- Padrão de busca: `findUnique(`, `findById(`, `SELECT * FROM ... WHERE id =` sem cláusula adicional de `user_id`/`owner_id`.
- Correção esperada: toda query por ID também filtra por `user_id = req.user.id` (ou equivalente), **e** RLS no banco como segunda camada.

### 2. RLS ausente ou incompleta (Supabase/Postgres)
- Verifique se `ENABLE ROW LEVEL SECURITY` existe para toda tabela que contém dados de usuário.
- Verifique se existem policies para `SELECT`, `INSERT`, `UPDATE`, `DELETE` — não só leitura.
- Sinal de alerta: uso extensivo da `service_role key` ou da `anon key` diretamente em rotas de API sem policy correspondente.

### 3. Sessão insegura / token exposto
- Procure `localStorage.setItem(`, `sessionStorage.setItem(` guardando JWT ou token de sessão.
- Verifique se cookies de sessão têm `HttpOnly`, `Secure` e `SameSite=Strict`/`Lax`.
- Verifique expiração (TTL) do token — tokens sem expiração ou com TTL muito longo são um risco.

### 4. Exposição de dados sem DTO
- Procure `res.json(user)`, `return userEntity`, `res.send(dbRow)` — devolvendo a entidade crua do banco em vez de um objeto filtrado.
- Sinal de alerta: campos como `password`, `password_hash`, `cpf`, `api_key`, `secret`, `stripe_customer_id` aparecendo em qualquer resposta de API.
- Correção esperada: camada de DTO/serializer explícita, ou pelo menos `select` explícito no ORM (nunca `select *`).

### 5. Confiança indevida em dados do client (fraude financeira)
- Procure endpoints de checkout/pagamento que recebem `amount`, `price`, `total`, `quantity` do body da requisição e usam esse valor diretamente na cobrança.
- Correção esperada: o preço/valor é sempre recalculado ou buscado no backend a partir do `productId`, nunca aceito do client.

### 6. Injeção (SQLi / XSS)
- Procure concatenação de strings em queries SQL (`\`SELECT * FROM x WHERE y = '${input}'\``) em vez de queries parametrizadas.
- Procure conteúdo gerado pelo usuário sendo renderizado sem sanitização (`dangerouslySetInnerHTML`, `v-html`, `{{{ }}}`) ou sem `sanitizeHtml`/equivalente.

### 7. Segredos e configuração
- Verifique se `.env`, `.env.local` etc. estão no `.gitignore` e **não** aparecem no histórico do Git (`git log --all --full-history -- .env`).
- Procure chaves/API keys hardcoded diretamente no código-fonte.
- Verifique se existe rate limiting em rotas de login, reset de senha e endpoints públicos sensíveis.

### 8. Hardening de infraestrutura (se houver acesso a configs de deploy/infra)
- Porta SSH na porta padrão (22) exposta publicamente.
- Banco de dados (Postgres/Redis/Mongo) acessível fora da rede interna.
- Ausência de HTTPS/redirect forçado de HTTP para HTTPS.

## Formato do relatório final

```
# Relatório de Auditoria — Método VCS

## Resumo
[N críticos, N altos, N atenção — prioridade de correção]

## Achados

### 🔥 [CRÍTICO] Título curto do problema
- Arquivo: caminho/arquivo.ts:42
- Problema: ...
- Como seria explorado: ...
- Correção:
```código corrigido```

[repetir para cada achado, ordenado por severidade]

## Checklist de Pré-Deploy
- [ ] UUIDs em rotas/tabelas públicas
- [ ] Backend valida ownership em toda query por ID
- [ ] RLS habilitado e testado em toda tabela sensível
- [ ] Sessão em cookie HttpOnly + Secure + SameSite
- [ ] DTOs protegendo campos sensíveis nas respostas
- [ ] Valor financeiro sempre validado no backend
- [ ] Rate limiting em login/reset de senha
- [ ] .env fora do Git, sem segredo hardcoded
- [ ] Porta SSH/banco não expostas publicamente
```

## Observações importantes
- Não presuma que um framework "resolve isso sozinho" (ex: Supabase não é seguro por padrão sem RLS configurado explicitamente).
- Se o projeto lida com dados pessoais de usuários no Brasil, mencione brevemente a relevância da LGPD (Art. 52) para os achados críticos, sem dar aconselhamento jurídico.
- Seja específico e acionável — o objetivo é que o usuário saia da auditoria com uma lista de correções que pode aplicar imediatamente, não uma lista genérica de boas práticas.
