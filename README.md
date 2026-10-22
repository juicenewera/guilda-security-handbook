# Guilda Security Handbook

Pacote independente para estudar, auditar e operar a segurança de uma aplicação web em uma VPS limitada.

O repositório reúne:

- modelo de ameaça e tratamento de dados;
- checklist de deploy e resposta a incidentes;
- skill de auditoria `security-audit-vibecoders`;
- método `auditprod` para auditorias reais em produção;
- Sentinela com alertas no Telegram;
- serviço systemd, timer, instalador e testes unitários.

Comece pelo [índice do pacote](./docs/seguranca-servidor-guilda/INDICE.md).

## Uso rápido

```bash
python -m unittest ops/sentinela/test_sentinela.py
sudo ops/sentinela/install-sentinela.sh
```

O token do Telegram, `chat_id`, credenciais de banco, IPs reais e logs de produção ficam fora deste repositório. Preencha a configuração somente no servidor, com permissão `600`.

Este material é uma referência operacional e deve ser adaptado ao provedor, ao modelo de ameaça e às obrigações de privacidade de cada projeto.
