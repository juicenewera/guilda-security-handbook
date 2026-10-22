# Auditoria de implementação

## Escopo revisado

Foram revisados o pacote público de segurança, `ops/sentinela`, os arquivos de serviço systemd, o instalador, os testes e as referências à integração do Telegram.

## Implementado

- Bot Telegram com envio de alertas e consulta de atualizações.
- Lista de chat autorizada para comandos operacionais.
- Deduplicação de alertas por janela de cooldown.
- Leitura incremental de logs e estado persistente fora do repositório.
- Detecção de sondagem, payloads suspeitos, força bruta HTTP, rate limit e falhas SSH.
- Alertas de container, novo administrador, divergência de Gold e rajadas de cadastro.
- Resumo diário e retrato agregado de uso, sem necessidade de enviar dados pessoais completos.
- Serviço `oneshot` e timer systemd com isolamento e timeout.
- Instalador idempotente com permissões restritas.
- Testes unitários para classificação de logs, comandos, cooldowns, uso e SSH.
- Documentação com tratamento de dados, resposta a incidentes e rotação de credenciais.

## Evidência local

```text
python -m unittest ops/sentinela/test_sentinela.py
14 testes passaram
git diff --check
sem erros de whitespace
```

## Pendências que exigem ambiente/decisão do operador

1. Preencher `TELEGRAM_BOT_TOKEN` e `TELEGRAM_CHAT_ID` somente na VPS.
2. Aplicar `scripts/ep-sentinela-uso.sql` no Supabase antes de usar o resumo de produto.
3. Instalar e habilitar o timer na VPS com `ops/sentinela/install-sentinela.sh`.
4. Validar o envio com `--teste` e revisar o journal.
5. Confirmar retenção de logs, backup e rotação das credenciais no provedor.
6. Configurar Fail2ban/firewall conforme o inventário real do servidor; a Sentinela apenas alerta e não bloqueia.

Esses itens não foram simulados localmente porque dependem de credenciais e estado externo. Não devem ser resolvidos com valores fictícios no Git.
