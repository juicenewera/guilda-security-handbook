# Guilda — base de segurança para servidor e aplicação

Este diretório registra, de forma reproduzível, como a Guilda protege uma aplicação web pequena rodando em uma VPS limitada. O objetivo é servir como base de estudo para outras equipes: explicar as camadas, as decisões e o tratamento correto dos dados sem publicar qualquer segredo de produção.

> Este material é uma referência operacional, não uma certificação. Adapte os comandos ao seu provedor, distribuição Linux, domínio, banco e modelo de ameaça.

## O modelo mental

Segurança não é um produto único. É uma sequência de barreiras:

```text
Internet
  ↓ TLS, headers e limite de requisições
Proxy reverso (Caddy/Nginx)
  ↓ apenas localhost
Aplicação web (Next.js em container)
  ↓ autenticação, autorização e validação de entrada
Banco/Storage gerenciado (RLS, funções e URLs assinadas)
  ↓ logs, alertas, backups e resposta a incidentes
Operação da VPS
```

Uma camada falhar não deve liberar automaticamente a seguinte.

Comece pelo [INDICE.md](./INDICE.md) para navegar pelo pacote e ver a auditoria de implementação.

## O que a Guilda utiliza

| Camada | Ferramenta | Função | Regra de segurança |
|---|---|---|---|
| Borda | Caddy com TLS automático | Termina HTTPS e encaminha para localhost | Não expor a porta da aplicação diretamente |
| Web | Next.js/Node.js | Renderização e APIs | Validar entrada, autenticar e autorizar no servidor |
| Runtime | Docker Compose | Isolamento e limites | Container sem root, filesystem somente leitura, caps removidas |
| Banco | Postgres gerenciado/Supabase | Dados da aplicação | RLS, privilégios mínimos e funções seguras |
| Arquivos | Storage privado | Vídeos, PDFs e apostilas | URLs assinadas e acesso baseado no direito à aula |
| Cache | Redis privado | Rate limit e cache temporário | Sem porta pública; falha deve degradar para Postgres |
| IA local | Ollama privado | Inferência e embeddings | Sem porta publicada; enviar somente o contexto necessário |
| Acesso | SSH com chave | Administração | Sem senha; Fail2ban para tentativas repetidas |
| Detecção | Sentinela + systemd timer | Agrega logs e alerta | Registrar sinais sem coletar conteúdo desnecessário |
| Entrega | Git + build imutável | Releases reproduzíveis | Deploy por commit, smoke test e rollback |

## Princípios de dados

Classifique antes de armazenar:

- **Público:** páginas de marketing e artigos que podem ser indexados.
- **Membro:** perfil, progresso, XP e atividade; visível somente conforme a regra do produto.
- **Privado:** e-mail, telefone, WhatsApp, transcrições e arquivos pagos.
- **Secreto:** chaves, tokens, cookies, credenciais de banco e webhooks.

Regras obrigatórias:

1. Segredos ficam em um cofre/variáveis do servidor, nunca em código, imagem Docker, log ou commit.
2. A chave pública do cliente não é autorização; toda operação sensível valida a sessão no servidor.
3. RLS deve proteger a tabela mesmo que alguém ignore a interface.
4. Retorne o mínimo de colunas necessário; não envie PII para o browser “por conveniência”.
5. Transcrições e arquivos privados usam a mesma regra de acesso do vídeo correspondente.
6. Logs devem registrar evento, horário, resultado e identificador técnico — não senha, token, cookie ou corpo sensível.
7. Dados usados por IA devem ser minimizados, autorizados e removidos quando deixarem de ser necessários.

## Estado atual e próximos passos

O hardening de container, rede privada, SSH por chave, health checks, fallback de Redis, logs de acesso e bloqueio operacional já existe no projeto. A auditoria contínua deve tratar como itens separados:

- rotação imediata de qualquer segredo que já tenha aparecido no histórico;
- revisão de privilégios de leitura de perfis e PII para usuários autenticados;
- webhooks em modo fail-closed, com comparação exata e idempotência;
- rate limit específico para sondagem HTTP, além do jail de SSH;
- persistência e retenção controlada dos bloqueios;
- revisão dos scripts SQL antigos para existir uma fonte canônica do schema;
- testes periódicos de autorização, upload, webhooks, XP e recursos pagos.

Veja o roteiro em [CHECKLIST.md](./CHECKLIST.md) e a operação diária em [OPERACAO.md](./OPERACAO.md).

O canal de alertas via Telegram e o processo Sentinela estão descritos em [TELEGRAM-SENTINELA.md](./TELEGRAM-SENTINELA.md). A pasta documenta a arquitetura e a operação, mas nunca inclui token, chat ID, IP ou log real.

## Skill de auditoria

O arquivo [SKILL.md](./SKILL.md) é a skill `security-audit-vibecoders` que usamos para conduzir auditorias ofensivas antes de deploy. Ela organiza a revisão em oito categorias: IDOR/BOLA, RLS, sessão, DTOs, confiança em dados do cliente, injeção, segredos/rate limit e hardening de infraestrutura. O relatório deve sempre apontar evidência, impacto, correção e checklist de pré-deploy.

## O que nunca publicar nesta pasta

- valores de tokens ou chaves;
- arquivos `.env`, dumps de banco ou URLs assinadas;
- IP real da VPS, nomes de usuários ou caminhos privados;
- e-mails, telefones, IDs de membros ou transcrições privadas;
- logs brutos que permitam correlacionar uma pessoa;
- comandos destrutivos sem confirmação e backup.

Antes de publicar, execute uma busca por padrões de segredo e revise o histórico do Git. Um segredo que apareceu no Git deve ser revogado e substituído mesmo depois de removido do arquivo.
