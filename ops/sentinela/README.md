# Sentinela da Guilda

Vigia da VPS que avisa no Telegram (e/ou WhatsApp) quando alguém tenta invadir.
Só lê; não bloqueia nada (bloqueio é com o fail2ban).

**Alerta na hora:** login SSH de IP fora de `SSH_ALLOW_IPS` · admin novo na Guilda ·
container sem saúde · saldo de Gold divergente do ledger · rajada de sondagem
(`/.env`, `/.git`, `wp-admin`…) · sondagem respondida com 2xx · força bruta no
login/API · força bruta no SSH. Mesmo alerta repetido: no máximo 1 a cada 30 min.

**Resumo diário** (9h de Brasília): tentativas das últimas 24 h por tipo + uso da Guilda
(online/pico, ativos 24 h/7 d, cadastros, foco, aulas concluídas, fórum, XP, destaques).

**Uso** (precisa de `scripts/ep-sentinela-uso.sql` aplicado): a cada 10 min lê
`ops_usage_snapshot()` (só service_role). Alerta de rajada de cadastros
(`SIGNUP_BURST`, padrão 15/h) e de recorde de online. No chat do bot, `/status`
responde o retrato na hora e `/ajuda` lista os comandos — só o `TELEGRAM_CHAT_ID`
configurado é atendido.

## Instalar / atualizar (da máquina do dono)
```bash
# Na VPS, a partir de uma cópia verificada do repositório:
sudo ops/sentinela/install-sentinela.sh
```
Se a instalação for feita remotamente, use um host configurado no seu inventário SSH, por exemplo `VPS_HOST`, e nunca publique o IP real no repositório:

```bash
ssh VPS_HOST 'mkdir -p /tmp/guilda-sentinela'
scp ops/sentinela/* VPS_HOST:/tmp/guilda-sentinela/
ssh VPS_HOST 'sudo bash /tmp/guilda-sentinela/install-sentinela.sh'
```
Config em `/opt/guilda-sentinela/sentinela.env` (modelo: `sentinela.env.example`, `chmod 600`).
Teste de envio: `python3 /opt/guilda-sentinela/sentinela.py --teste`.

Depende do log de acesso do Caddy em `/var/log/caddy/guilda-access.log` (bloco `log` em `deploy/Caddyfile`).

## Testes
`python -m unittest ops/sentinela/test_sentinela.py`
