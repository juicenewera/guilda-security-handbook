# Checklist compartilhável

## Antes de colocar no ar

- [ ] Domínio usa HTTPS e redireciona HTTP para HTTPS.
- [ ] Proxy é o único serviço público.
- [ ] SSH aceita chave e rejeita senha.
- [ ] Usuários administrativos são individuais; não compartilhar `root`.
- [ ] Firewall permite somente portas necessárias.
- [ ] Containers não rodam como root e não têm caps desnecessárias.
- [ ] Banco e Redis não têm porta pública.
- [ ] Segredos estão fora do Git e fora da imagem.
- [ ] RLS foi testado com anônimo, membro comum, membro autorizado e admin.
- [ ] Upload, webhook, reset de senha e login têm limite e validação.
- [ ] Health check, backup e rollback foram testados.
- [ ] Logs não contêm tokens, senhas, cookies ou PII desnecessária.

## Em cada release

- [ ] Revisar diff e dependências.
- [ ] Executar testes unitários, integração, typecheck e lint.
- [ ] Rodar busca de segredos no working tree e no commit.
- [ ] Construir imagem a partir do commit correto.
- [ ] Rodar smoke test isolado.
- [ ] Ativar somente após `/api/live` e dependências estarem saudáveis.
- [ ] Confirmar que a release anterior continua disponível para rollback.
- [ ] Verificar logs após 5–15 minutos.

## Revisão semanal

- [ ] Verificar logins SSH aceitos e falhos.
- [ ] Revisar alertas de scanner e rate limit.
- [ ] Conferir IPs bloqueados e validade dos banimentos.
- [ ] Confirmar backups e testar uma restauração pequena.
- [ ] Atualizar dependências críticas.
- [ ] Revisar membros administrativos e webhooks ativos.
- [ ] Confirmar que recursos privados continuam protegidos por RLS.
- [ ] Remover artefatos temporários, dumps e arquivos `.env`.

## Sinais de incidente confirmado

Trate como incidente, e não apenas sondagem, quando houver qualquer um destes sinais:

- login SSH aceito inesperado;
- criação/alteração de usuário administrativo;
- segredo acessado ou exposto;
- alteração de RLS, webhook ou entitlement sem deploy conhecido;
- upload, download privado ou chamada administrativa fora do padrão;
- processo/container desconhecido persistente;
- dados alterados sem request legítimo.

Uma sequência de `404`, `401`, `403` e redirecionamentos, sem login aceito ou mudança de estado, normalmente é sondagem recusada — ainda deve ser registrada e usada para melhorar detecção.
