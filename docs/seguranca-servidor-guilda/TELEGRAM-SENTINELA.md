# Telegram + Sentinela

O bot do Telegram funciona como um canal operacional para alertas de segurança e saúde da Guilda. Ele não substitui autenticação, firewall, backup ou monitoramento: apenas reduz o tempo entre um evento e a resposta da equipe.

## O que já existe no projeto

- Implementação: [`ops/sentinela/sentinela.py`](../../ops/sentinela/sentinela.py)
- Configuração sem segredos: [`ops/sentinela/sentinela.env.example`](../../ops/sentinela/sentinela.env.example)
- Manual operacional: [`ops/sentinela/README.md`](../../ops/sentinela/README.md)
- Instalador reproduzível: [`ops/sentinela/install-sentinela.sh`](../../ops/sentinela/install-sentinela.sh)
- Execução agendada: `ops/sentinela/guilda-sentinela.service` e `ops/sentinela/guilda-sentinela.timer`

O processo lê sinais do host e do Caddy, agrega eventos e envia mensagens para um único chat autorizado. Também oferece comandos operacionais restritos, como `/status` e `/ajuda`.

## Criar o bot

1. No Telegram, abra `@BotFather`.
2. Execute `/newbot`, escolha nome e username terminando em `bot`.
3. Guarde o token em um cofre ou variável de ambiente. Nunca o coloque no Git, em screenshot, ticket ou log.
4. Envie uma mensagem ao bot pelo chat que receberá os alertas.
5. Obtenha o `chat_id` pelo método documentado no manual da Sentinela. Use apenas o ID do chat administrativo.

## Configuração segura

Copie o exemplo para um caminho fora do repositório e preencha somente no servidor:

```bash
install -d -m 700 /opt/guilda-sentinela
install -m 600 ops/sentinela/sentinela.env.example /opt/guilda-sentinela/sentinela.env
${EDITOR:-vi} /opt/guilda-sentinela/sentinela.env
```

Valores esperados:

```dotenv
TELEGRAM_BOT_TOKEN=<token fornecido pelo BotFather>
TELEGRAM_CHAT_ID=<chat administrativo>
```

O arquivo de exemplo também permite apontar o log do Caddy, o container web, limites de rajada de cadastro e horário do resumo diário. Mantenha os valores específicos da infraestrutura somente no servidor.

Verifique permissões e exposição antes de ativar:

```bash
chmod 600 /opt/guilda-sentinela/sentinela.env
systemctl enable --now guilda-sentinela.timer
systemctl status guilda-sentinela.timer --no-pager
```

## Alertas cobertos

- falhas repetidas e logins SSH aceitos fora da lista autorizada;
- sondagem de arquivos sensíveis e caminhos administrativos;
- rajadas anormais de cadastro ou chamadas HTTP;
- container sem health check ou aplicação indisponível;
- resumo de uso da Guilda e eventos relevantes de operação.

Mensagens devem conter somente evento, horário, contagem e identificadores técnicos mínimos. Nunca envie senha, token, cookie, corpo de requisição, transcrição privada ou PII desnecessária.

## Teste e resposta

Faça um teste controlado após configurar o token:

```bash
python3 /opt/guilda-sentinela/sentinela.py --teste
journalctl -u guilda-sentinela.service -n 100 --no-pager
```

Quando um alerta chegar:

1. confirme se é falso positivo consultando os logs locais;
2. preserve horário, origem, rota e resultado, sem copiar dados sensíveis;
3. bloqueie a origem somente após validar o escopo e registrar a ação;
4. revogue credenciais se houver indício de exposição;
5. faça rollback ou coloque a aplicação em modo seguro se a integridade estiver incerta;
6. registre causa, correção e teste de retorno.

## Limites e cuidados

- Restrinja comandos do bot ao `TELEGRAM_CHAT_ID` configurado.
- Use deduplicação e limites para não transformar o alerta em negação de serviço ou spam.
- Escape Markdown/HTML antes de enviar mensagens construídas a partir de logs.
- Não permita que mensagens do Telegram executem shell arbitrário.
- Rotacione o token pelo BotFather ao menor sinal de vazamento e reinicie o serviço.
- Tenha um canal alternativo: se Telegram ou a API estiver indisponível, os logs locais e o systemd continuam sendo a fonte de evidência.

O Telegram é uma camada de notificação e operação assistida; a decisão de bloquear, alterar permissões ou recuperar dados continua sendo feita com revisão humana e registro de auditoria.
