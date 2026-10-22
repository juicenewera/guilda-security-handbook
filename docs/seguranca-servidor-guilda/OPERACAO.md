# Operação segura

## 1. Preparar a VPS

- Atualizar o sistema e remover serviços que não serão usados.
- Criar um usuário administrativo individual com `sudo`.
- Instalar somente SSH por chave; desativar senha e login interativo.
- Restringir portas públicas ao HTTPS e, quando possível, a uma allowlist administrativa.
- Ativar atualizações de segurança e sincronização de horário.
- Manter backup testado da configuração e do banco.

Valide a configuração efetiva, não apenas o arquivo que você editou:

```bash
sshd -T | grep -E 'passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin'
ss -lntup
```

## 2. Endurecer containers

Para serviços web e workers:

- imagem construída de um commit conhecido;
- usuário sem privilégios;
- `read_only: true` quando possível;
- `cap_drop: [ALL]`;
- `no-new-privileges`;
- limites de CPU, memória, PIDs e tamanho de temporários;
- portas publicadas somente em `127.0.0.1` ou não publicadas;
- health check que valide uma rota mínima;
- rede interna separada para banco, Redis e modelos.

Não monte o socket Docker dentro da aplicação. Não coloque `.env` no contexto de build. Use secrets de BuildKit somente durante a etapa que precisa deles e remova qualquer cópia materializada antes da imagem final.

## 3. Autenticação e autorização

Autenticação responde “quem é a pessoa?”. Autorização responde “o que ela pode fazer?”. As duas devem existir no servidor.

- OAuth/PKCE: validar o retorno, usar estado/verifier e aceitar somente origens esperadas.
- Sessão: não confiar em `user_id` vindo do corpo da requisição.
- Admin/fundador: checar no servidor e no banco; esconder botão não é controle.
- Conteúdo pago: verificar entitlement antes de vídeo, transcrição ou arquivo.
- Webhook: validar assinatura/token, schema, timestamp, idempotência e produto permitido.
- Erro: responder sem revelar se um e-mail existe, uma chave existe ou qual regra interna falhou.

Casos mínimos de teste:

1. visitante anônimo não lê perfil, transcrição ou arquivo privado;
2. membro A não lê o recurso liberado somente para membro B;
3. usuário comum não chama função administrativa;
4. webhook repetido não duplica pagamento, XP ou acesso;
5. payload com curingas, campos extras, e-mail inválido e valores enormes falha fechado.

## 4. Banco e Storage

- Ativar RLS em toda tabela exposta ao cliente.
- Revogar privilégios amplos e conceder apenas as colunas necessárias.
- Preferir RPCs pequenas e `SECURITY DEFINER` com `search_path` controlado quando uma operação atravessar várias tabelas.
- Nunca usar service role no browser.
- Normalizar identificadores e usar igualdade exata para e-mail, slug e IDs.
- Colocar limites e idempotency keys em operações que concedem XP, Gold, acesso ou créditos.
- Storage privado por padrão; gerar URL assinada curta depois de checar autorização.
- Limpar upload órfão quando a atualização do registro falhar.

## 5. Redis e rate limit

Redis é otimização, não deve ser o ponto único de disponibilidade do login:

- conexão inicial deve falhar rápido;
- reconexão deve ter intervalo limitado;
- comandos devem possuir timeout;
- se Redis cair, o rate limit usa uma estratégia de fallback no banco;
- não deixar comandos congelados em fila indefinidamente;
- nunca publicar Redis na internet.

Rate limit deve existir por rota e por identidade quando aplicável. Login, reset de senha, webhooks, upload e endpoints de busca merecem limites diferentes. Scanner de arquivos sensíveis deve gerar sinal próprio, sem bloquear usuários legítimos por uma única requisição.

## 6. Logs e Sentinela

Colete somente o necessário:

- Caddy: horário, IP, método, rota, status, duração e user-agent quando útil;
- SSH: sucesso, falha, usuário e origem;
- aplicação: evento de segurança, resultado e request id;
- banco: migração e falha operacional, nunca payload secreto.

O Sentinela agrega contagens de scanner, falhas de autenticação, rate limit e SSH. Um alerta “tentativa” não significa “invasão”: sempre correlacione horário, rota, status e existência de autenticação aceita.

## 7. Resposta a incidente

1. **Conter:** bloquear o IP ou token comprometido sem derrubar a aplicação inteira.
2. **Preservar:** copiar logs e registrar horário, commit, imagem e mudanças feitas.
3. **Determinar alcance:** procurar autenticação aceita, alterações de privilégio, uploads, webhooks e consultas anormais.
4. **Revogar:** rotacionar segredos, invalidar sessões e remover chaves suspeitas.
5. **Corrigir:** fechar a causa, adicionar teste de regressão e revisar rotas relacionadas.
6. **Recuperar:** deploy reproduzível, smoke test, monitoramento e rollback pronto.
7. **Comunicar:** separar fato comprovado, hipótese e dado ainda desconhecido.

Nunca atribua um IP a uma pessoa sem evidência adicional. IP residencial, proxy ou user-agent não identifica o autor.

## 8. Deploy e rollback

O release deve ser imutável e rastreável:

```text
commit → archive verificado → build isolado → smoke test → troca atômica → health check
                                                     ↘ falha: rollback
```

Não altere arquivos dentro do container em produção. Não faça `docker compose down` como primeira opção em horário de uso. Preserve a release anterior até o novo serviço passar pelos checks.
