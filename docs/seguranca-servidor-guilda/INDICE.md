# Índice do pacote de segurança

Este diretório é a porta de entrada para a documentação pública de segurança da Guilda. Ele explica o modelo e aponta para os artefatos executáveis sem misturar segredos de produção com o código da aplicação.

## Conteúdo

| Arquivo | Uso |
|---|---|
| [README.md](./README.md) | Modelo de ameaça, camadas e regras de dados |
| [OPERACAO.md](./OPERACAO.md) | Rotinas de VPS, deploy, logs e incidentes |
| [CHECKLIST.md](./CHECKLIST.md) | Checklist antes do deploy e revisão periódica |
| [TELEGRAM-SENTINELA.md](./TELEGRAM-SENTINELA.md) | Bot Telegram, alertas e operação assistida |
| [SKILL.md](./SKILL.md) | Skill de auditoria ofensiva usada no projeto |
| [SKILLS-RECOMENDADAS.md](./SKILLS-RECOMENDADAS.md) | Skills complementares e método de raciocínio |
| [AUDITORIA-IMPLEMENTACAO.md](./AUDITORIA-IMPLEMENTACAO.md) | O que está implementado, evidência e pendências |
| [AUDITORIA-KIPPERDEV-2026-10-22.md](./AUDITORIA-KIPPERDEV-2026-10-22.md) | Auditoria completa baseada no guia do Drive e plano por etapas |

## Código operacional

O código executável permanece em [`ops/sentinela/`](../../ops/sentinela/), que é a fonte única para evitar duas versões divergentes:

- `sentinela.py`: coleta, classificação, alertas e comandos autorizados;
- `sentinela.env.example`: configuração sem credenciais;
- `guilda-sentinela.service` e `.timer`: execução restrita pelo systemd;
- `install-sentinela.sh`: instalação idempotente;
- `test_sentinela.py`: testes unitários das regras de detecção.

## Regra de publicação

Antes de publicar este pacote, execute uma busca por tokens, chaves privadas, URLs assinadas, IPs reais, dumps e PII. O token do Telegram, o `chat_id`, as credenciais Supabase e os caminhos/hosts específicos pertencem somente ao ambiente protegido.
