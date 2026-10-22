#!/usr/bin/env python3
"""Sentinela da Guilda: lê os sinais da VPS e avisa no Telegram (e/ou WhatsApp).

Roda a cada 2 min (guilda-sentinela.timer). Só LÊ: logs do Caddy, journal do
SSH, saúde do container e duas consultas ao Supabase (admins, divergência do
Gold). Não bloqueia nada — bloqueio é com o fail2ban.

Alerta na hora: login SSH de IP fora da lista, admin novo, container sem saúde,
divergência no saldo de Gold, rajada de sondagem (/.env, /.git, wp-admin...),
sondagem respondida com 2xx (possível exposição), força bruta no login/API.
Resumo diário: contagem do dia por tipo ("17 tentativas de invasão hoje").

Config: /opt/guilda-sentinela/sentinela.env (ver sentinela.env.example).
Estado: /var/lib/guilda-sentinela/state.json
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

CONFIG_PATH = os.environ.get('SENTINELA_CONFIG', '/opt/guilda-sentinela/sentinela.env')
STATE_PATH = os.environ.get('SENTINELA_STATE', '/var/lib/guilda-sentinela/state.json')

# Caminhos que só robô de ataque pede. Comparado só com o CAMINHO (sem a
# query): o gate redireciona pra /login?next=/wp-admin/..., e esse /login 200
# não é exposição (falso alarme real de 2026-10-20).
SCANNER_PATH_RE = re.compile(
    r'(/\.env|/\.git(/|$)|/\.aws|/\.ssh|/\.DS_Store|wp-(admin|login|content|includes)|xmlrpc\.php|'
    r'phpmyadmin|/pma(/|$)|\.php$|/cgi-bin/|/actuator|/server-status|/vendor/phpunit|'
    r'/boaform|/HNAP1|/config\.json$|/\.vscode|/backup\.(zip|sql|tar)|/dump\.sql|/id_rsa|/\.htaccess)',
    re.IGNORECASE,
)
# Carga de ataque em qualquer parte da URL: conta como tentativa, nunca como exposição.
SCANNER_PAYLOAD_RE = re.compile(
    r'(/etc/passwd|\.\./|%2e%2e|union(\s|%20|\+)+select|<script|%3cscript)',
    re.IGNORECASE,
)
AUTH_PATH_RE = re.compile(r'^/(api/|admin|login|auth/)')

SSH_ACCEPT_RE = re.compile(r'Accepted (\S+) for (\S+) from (\S+)')
SSH_FAIL_RE = re.compile(r'(?:Failed password for (?:invalid user )?(\S+) from (\S+)|Invalid user (\S+) from (\S+))')

COOLDOWN_S = 30 * 60
SCANNER_BURST = 5      # sondas do mesmo IP numa rodada
AUTH_BURST = 30        # 401/403 do mesmo IP numa rodada
RATE_BURST = 20        # 429 do mesmo IP numa rodada
SSH_FAIL_BURST = 20    # senhas erradas numa rodada
SIGNUP_BURST = 15      # cadastros numa hora (pico de divulgação... ou robô)
USAGE_EVERY_S = 10 * 60  # retrato de uso do banco a cada 10 min
BRT = timezone(timedelta(hours=-3))  # Brasília (sem horário de verão desde 2019)


# ---------------------------------------------------------------- config/estado

def load_env(path: str) -> dict[str, str]:
    env: dict[str, str] = {}
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return env


def load_state(path: str) -> dict:
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(path: str, state: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(state, f)
    os.replace(tmp, path)


# ---------------------------------------------------------------- análise (pura, testada)

def analyze_caddy(lines: list[str]) -> dict:
    """Classifica linhas JSON do log do Caddy."""
    scanner = Counter()
    scanner_ok: list[tuple[str, str, int]] = []
    auth_fail = Counter()
    rate_limited = Counter()
    for raw in lines:
        try:
            e = json.loads(raw)
        except json.JSONDecodeError:
            continue
        req = e.get('request') or {}
        ip = req.get('client_ip') or req.get('remote_ip') or '?'
        uri = req.get('uri') or ''
        status = int(e.get('status') or 0)
        path = uri.split('?', 1)[0]
        if SCANNER_PATH_RE.search(path):
            scanner[ip] += 1
            if 200 <= status < 300:
                scanner_ok.append((ip, uri[:120], status))
        elif SCANNER_PAYLOAD_RE.search(uri):
            scanner[ip] += 1
        elif status in (401, 403) and AUTH_PATH_RE.search(uri):
            auth_fail[ip] += 1
        if status == 429:
            rate_limited[ip] += 1
    return {'scanner': scanner, 'scanner_ok': scanner_ok, 'auth_fail': auth_fail, 'rate_limited': rate_limited}


def analyze_ssh(lines: list[str], allow_ips: set[str]) -> dict:
    accepted_unknown: list[tuple[str, str, str]] = []
    failures = Counter()
    for line in lines:
        m = SSH_ACCEPT_RE.search(line)
        if m:
            method, user, ip = m.groups()
            if ip not in allow_ips:
                accepted_unknown.append((user, ip, method))
            continue
        m = SSH_FAIL_RE.search(line)
        if m:
            ip = m.group(2) or m.group(4)
            failures[ip] += 1
    return {'accepted_unknown': accepted_unknown, 'failures': failures}


def cooldown_ok(state: dict, key: str, now: float) -> bool:
    last = state.setdefault('cooldown', {}).get(key)
    if last is not None and now - last < COOLDOWN_S:
        return False
    state['cooldown'][key] = now
    return True


def build_alerts(caddy: dict, ssh: dict, state: dict, now: float) -> list[str]:
    alerts: list[str] = []
    for user, ip, method in ssh['accepted_unknown']:
        if cooldown_ok(state, f'ssh-ok:{ip}', now):
            alerts.append(f'🚨 LOGIN NO SERVIDOR de IP desconhecido\nusuário {user} · IP {ip} · método {method}\nSe não foi você: troque a senha/chave do root agora.')
    for ip, uri, status in caddy['scanner_ok']:
        if cooldown_ok(state, f'scan-ok:{ip}:{uri}', now):
            alerts.append(f'🚨 SONDA RESPONDIDA COM {status}\n{uri}\nIP {ip} — confira se algo sensível ficou exposto.')
    for ip, n in caddy['scanner'].items():
        if n >= SCANNER_BURST and cooldown_ok(state, f'scan:{ip}', now):
            alerts.append(f'🛡️ Robô sondando o site: {n} tentativas de achar arquivos sensíveis\nIP {ip} · todas recusadas')
    for ip, n in caddy['auth_fail'].items():
        if n >= AUTH_BURST and cooldown_ok(state, f'auth:{ip}', now):
            alerts.append(f'⚠️ Força bruta no login/API: {n} acessos negados (401/403)\nIP {ip}')
    for ip, n in caddy['rate_limited'].items():
        if n >= RATE_BURST and cooldown_ok(state, f'rate:{ip}', now):
            alerts.append(f'⚠️ Limite de tentativas acionado {n}× para o IP {ip}')
    total_ssh_fail = sum(ssh['failures'].values())
    if total_ssh_fail >= SSH_FAIL_BURST and cooldown_ok(state, 'ssh-brute', now):
        top = ', '.join(f'{ip} ({n})' for ip, n in ssh['failures'].most_common(3))
        alerts.append(f'⚠️ Força bruta no SSH: {total_ssh_fail} senhas erradas agora\nmais ativos: {top}')
    return alerts


def add_to_daily(state: dict, caddy: dict, ssh: dict) -> None:
    d = state.setdefault('daily', defaultdict(int))
    d['scanner'] = d.get('scanner', 0) + sum(caddy['scanner'].values())
    d['auth_fail'] = d.get('auth_fail', 0) + sum(caddy['auth_fail'].values())
    d['rate_limited'] = d.get('rate_limited', 0) + sum(caddy['rate_limited'].values())
    d['ssh_fail'] = d.get('ssh_fail', 0) + sum(ssh['failures'].values())
    ips = set(state.get('daily_ips', []))
    ips.update(caddy['scanner'].keys(), caddy['auth_fail'].keys(), ssh['failures'].keys())
    state['daily_ips'] = sorted(ips)[:500]


def daily_summary(state: dict) -> str:
    d = state.get('daily', {})
    total = sum(int(v) for v in d.values())
    ips = len(state.get('daily_ips', []))
    if total == 0:
        return '🛡️ Guilda — resumo de segurança de ontem: nenhuma tentativa de invasão registrada.'
    return (
        f'🛡️ Guilda — {total} tentativas de invasão nas últimas 24 h, de {ips} IPs. Nenhuma passou.\n'
        f'• robôs procurando arquivos sensíveis: {d.get("scanner", 0)}\n'
        f'• senhas erradas no SSH: {d.get("ssh_fail", 0)}\n'
        f'• acessos negados no login/API: {d.get("auth_fail", 0)}\n'
        f'• bloqueios por excesso de tentativas: {d.get("rate_limited", 0)}'
    )


# ---------------------------------------------------------------- uso da Guilda (puro, testado)
# Vem de ops_usage_snapshot() (scripts/ep-sentinela-uso.sql): números agregados,
# nada pessoal além de @username nos destaques.

def _n(snap: dict, k: str) -> int:
    try:
        return int(snap.get(k) or 0)
    except (TypeError, ValueError):
        return 0


def track_usage(snap: dict, state: dict, now: float, signup_burst: int = SIGNUP_BURST) -> list[str]:
    """Guarda o pico de online do dia e o recorde; devolve alertas de uso."""
    alerts: list[str] = []
    online = _n(snap, 'online_agora')
    hora = datetime.fromtimestamp(now, BRT).strftime('%H:%M')

    peak = state.setdefault('usage_peak', {'online': 0, 'hora': None})
    if online > peak.get('online', 0):
        state['usage_peak'] = {'online': online, 'hora': hora}

    record = state.get('usage_record')
    if record is None:
        state['usage_record'] = {'online': online, 'quando': hora}   # 1ª leitura: só registra
    elif online > record.get('online', 0):
        state['usage_record'] = {'online': online, 'quando': datetime.fromtimestamp(now, BRT).strftime('%d/%m %H:%M')}
        if online >= 5 and cooldown_ok(state, 'usage-record', now):
            alerts.append(f'🏆 Recorde de gente online na Guilda: {online} agora ({_n(snap, "em_foco_agora")} em foco).')

    cad = _n(snap, 'cadastros_1h')
    if cad >= signup_burst and cooldown_ok(state, 'signup-burst', now):
        alerts.append(
            f'📈 {cad} cadastros na última hora (normal é bem menos).\n'
            'Se não teve divulgação agora, pode ser robô criando conta — confira em Admin → Usuários.'
        )
    return alerts


def format_usage(snap: dict, peak: dict | None = None, titulo: str = '📊 Guilda agora') -> str:
    n = lambda k: _n(snap, k)  # noqa: E731
    foco_h, foco_m = divmod(n('foco_min_24h'), 60)
    foco_txt = f'{foco_h}h {foco_m:02d}min' if foco_h else f'{foco_m} min'
    linhas = [
        titulo,
        f'• online agora: {n("online_agora")} ({n("em_foco_agora")} em foco)',
    ]
    if peak and peak.get('hora'):
        linhas.append(f'• pico de online: {peak.get("online", 0)} às {peak["hora"]}')
    linhas += [
        f'• ativos: {n("ativos_24h")} nas últimas 24 h · {n("ativos_7d")} em 7 dias (de {n("membros")} membros, {n("fundadores")} fundadores)',
        f'• cadastros: {n("cadastros_24h")} em 24 h · {n("cadastros_7d")} em 7 dias'
        + (f' ({n("sem_onboarding_7d")} pararam antes de terminar o cadastro)' if n('sem_onboarding_7d') else ''),
        f'• foco: {foco_txt} somados por {n("foco_pessoas_24h")} pessoa(s) em {n("foco_sessoes_24h")} sessão(ões)',
        f'• aulas concluídas: {n("aulas_concluidas_24h")} por {n("alunos_24h")} aluno(s)',
        f'• fórum: {n("posts_24h")} posts · {n("comentarios_24h")} comentários · {n("curtidas_24h")} curtidas',
        f'• XP distribuído: {n("xp_24h")}',
    ]
    top = snap.get('top_foco_24h') or []
    if top:
        linhas.append('• mais focados: ' + ', '.join(f'@{t.get("username")} ({int(t.get("min") or 0)} min)' for t in top[:3]))
    aula = snap.get('aula_top_24h') or {}
    if aula.get('titulo'):
        linhas.append(f'• aula mais concluída: {aula["titulo"]} ({int(aula.get("vezes") or 0)}×)')
    if active_ratio := (n('ativos_7d') / n('membros') if n('membros') else 0):
        linhas.append(f'• {round(active_ratio * 100)}% dos membros apareceram na semana')
    return '\n'.join(linhas)


def parse_commands(updates: list, chat_id: str) -> tuple[list[str], int | None]:
    """Comandos do dono no chat do bot (/status, /uso, /ajuda). Ignora qualquer outro chat."""
    cmds: list[str] = []
    last_id = None
    for u in updates or []:
        uid = u.get('update_id')
        if isinstance(uid, int):
            last_id = uid if last_id is None else max(last_id, uid)
        msg = u.get('message') or {}
        if str((msg.get('chat') or {}).get('id')) != str(chat_id):
            continue
        text = (msg.get('text') or '').strip().split('@')[0].split(' ')[0].lower()
        if text in ('/status', '/uso', '/agora'):
            cmds.append('status')
        elif text in ('/ajuda', '/help', '/start'):
            cmds.append('ajuda')
    return cmds, last_id


AJUDA = (
    '🤖 Sentinela da Guilda\n'
    '/status — quem está online, em foco, cadastros e uso das últimas 24 h\n'
    'Sozinho eu aviso: invasão, site fora do ar, admin novo, Gold divergente, '
    'rajada de cadastros e recorde de online. Resumo todo dia às 9h.'
)


# ---------------------------------------------------------------- coleta (efeitos)

def read_new_lines(path: str, state: dict, key: str) -> list[str]:
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return []
    pos = state.setdefault('offsets', {}).get(key, {})
    offset = pos.get('offset', st.st_size)  # 1ª execução: começa do fim
    if pos.get('inode') != st.st_ino or st.st_size < offset:
        offset = 0 if pos else st.st_size
    with open(path, 'rb') as f:
        f.seek(offset)
        data = f.read(5_000_000)
        state['offsets'][key] = {'inode': st.st_ino, 'offset': offset + len(data)}
    return data.decode('utf-8', 'replace').splitlines()


def read_ssh(state: dict) -> list[str]:
    since = state.get('ssh_since') or int(time.time()) - 180
    now = int(time.time())
    try:
        out = subprocess.run(
            ['journalctl', '-u', 'ssh', '-u', 'sshd', '--since', f'@{since}', '--until', f'@{now}', '--no-pager', '-q'],
            capture_output=True, text=True, timeout=30,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    state['ssh_since'] = now
    return out.splitlines()


def container_health(name: str) -> str:
    try:
        return subprocess.run(
            ['docker', 'inspect', '-f', '{{.State.Health.Status}}', name],
            capture_output=True, text=True, timeout=20,
        ).stdout.strip() or 'ausente'
    except (OSError, subprocess.TimeoutExpired):
        return 'desconhecido'


def supabase_get(url: str, key: str, path: str):
    req = urllib.request.Request(f'{url.rstrip("/")}/rest/v1/{path}', headers={'apikey': key, 'Authorization': f'Bearer {key}'})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


def supabase_rpc(url: str, key: str, fn: str):
    req = urllib.request.Request(
        f'{url.rstrip("/")}/rest/v1/rpc/{fn}', data=b'{}', method='POST',
        headers={'apikey': key, 'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'},
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


def telegram_updates(token: str, offset: int | None) -> list:
    q = f'?timeout=0&allowed_updates=%5B%22message%22%5D' + (f'&offset={offset}' if offset is not None else '')
    with urllib.request.urlopen(f'https://api.telegram.org/bot{token}/getUpdates{q}', timeout=15) as r:
        body = json.loads(r.read().decode())
    return body.get('result', []) if body.get('ok') else []


def send(env: dict, text: str) -> None:
    sent = False
    token, chat = env.get('TELEGRAM_BOT_TOKEN'), env.get('TELEGRAM_CHAT_ID')
    if token and chat:
        body = json.dumps({'chat_id': chat, 'text': text, 'disable_web_page_preview': True}).encode()
        req = urllib.request.Request(f'https://api.telegram.org/bot{token}/sendMessage', data=body, headers={'Content-Type': 'application/json'})
        try:
            urllib.request.urlopen(req, timeout=15).read()
            sent = True
        except urllib.error.URLError as e:
            print(f'telegram falhou: {e}', file=sys.stderr)
    hook = env.get('WHATSAPP_WEBHOOK_URL')
    if hook:
        headers = {'Content-Type': 'application/json'}
        if env.get('WHATSAPP_WEBHOOK_TOKEN'):
            headers['Authorization'] = f'Bearer {env["WHATSAPP_WEBHOOK_TOKEN"]}'
        body = json.dumps({'to': env.get('WHATSAPP_TO', ''), 'text': text}).encode()
        try:
            urllib.request.urlopen(urllib.request.Request(hook, data=body, headers=headers), timeout=15).read()
            sent = True
        except urllib.error.URLError as e:
            print(f'whatsapp falhou: {e}', file=sys.stderr)
    if not sent:
        print(f'[sem canal configurado] {text}')


# ---------------------------------------------------------------- rodada

def run(test: bool = False) -> int:
    env = load_env(CONFIG_PATH)
    if test:
        send(env, '✅ Sentinela da Guilda ligado. Você vai receber aqui os alertas de invasão e o resumo diário.')
        return 0

    state = load_state(STATE_PATH)
    now = time.time()
    caddy = analyze_caddy(read_new_lines(env.get('CADDY_LOG', '/var/log/caddy/guilda-access.log'), state, 'caddy'))
    allow = {ip.strip() for ip in env.get('SSH_ALLOW_IPS', '').split(',') if ip.strip()}
    ssh = analyze_ssh(read_ssh(state), allow)
    alerts = build_alerts(caddy, ssh, state, now)

    health = container_health(env.get('CONTAINER', 'guilda-web'))
    if health not in ('healthy', 'desconhecido') and cooldown_ok(state, 'container', now):
        alerts.append(f'🔴 Site fora do ar: container {env.get("CONTAINER", "guilda-web")} está "{health}".')

    # Supabase: admin novo e divergência do Gold (lê a chave do env de produção).
    prod = load_env(env.get('PROD_ENV', '/opt/gypsi-guilda/secrets/production.env'))
    url, key = prod.get('NEXT_PUBLIC_SUPABASE_URL'), prod.get('SUPABASE_SERVICE_ROLE_KEY')
    if url and key:
        try:
            admins = sorted(r.get('username') or r.get('id') for r in supabase_get(url, key, 'profiles?is_admin=eq.true&select=id,username'))
            known = state.get('admins')
            if known is not None:
                novos = [a for a in admins if a not in known]
                if novos and cooldown_ok(state, 'admins:' + ','.join(novos), now):
                    alerts.append(f'🚨 NOVO ADMIN na Guilda: {", ".join(novos)}\nSe não foi você, remova o cargo agora.')
            state['admins'] = admins
        except (urllib.error.URLError, ValueError, TypeError) as e:
            print(f'admins: {e}', file=sys.stderr)
        try:
            drift = supabase_get(url, key, 'gold_balance_drift?select=*&limit=5')
            if drift and cooldown_ok(state, 'gold-drift', now):
                alerts.append(f'🚨 Saldo de Gold diferente do histórico em {len(drift)} perfil(is). Possível edição direta no banco.')
        except urllib.error.HTTPError as e:
            if e.code != 404:
                print(f'gold_drift: {e}', file=sys.stderr)
        except (urllib.error.URLError, ValueError) as e:
            print(f'gold_drift: {e}', file=sys.stderr)

    # Uso da Guilda: retrato do banco (no máximo 1 consulta por rodada).
    snap_cache: list = []

    def usage():
        if not snap_cache:
            snap_cache.append(None)
            if url and key:
                try:
                    snap_cache[0] = supabase_rpc(url, key, 'ops_usage_snapshot')
                except (urllib.error.URLError, ValueError) as e:
                    print(f'uso: {e}', file=sys.stderr)
        return snap_cache[0]

    if now - state.get('usage_ts', 0) >= USAGE_EVERY_S:
        snap = usage()
        if snap:
            alerts += track_usage(snap, state, now, int(env.get('SIGNUP_BURST', SIGNUP_BURST)))
        state['usage_ts'] = now

    for a in alerts:
        send(env, a)

    # Comandos do dono no Telegram (/status, /ajuda) — só do chat configurado.
    token, chat = env.get('TELEGRAM_BOT_TOKEN'), env.get('TELEGRAM_CHAT_ID')
    if token and chat:
        try:
            first = 'tg_offset' not in state
            cmds, last = parse_commands(telegram_updates(token, state.get('tg_offset')), chat)
            if last is not None:
                state['tg_offset'] = last + 1
            elif first:
                state['tg_offset'] = None
            for cmd in ([] if first else cmds):   # 1ª rodada: não responde mensagem antiga
                if cmd == 'status':
                    snap = usage()
                    send(env, format_usage(snap, state.get('usage_peak')) if snap
                         else '⚠️ Não consegui ler os números agora (falta aplicar scripts/ep-sentinela-uso.sql?).')
                else:
                    send(env, AJUDA)
        except (urllib.error.URLError, ValueError) as e:
            print(f'telegram comandos: {e}', file=sys.stderr)

    # Resumo diário (hora em UTC; 12 = 9h de Brasília).
    add_to_daily(state, caddy, ssh)
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    hour = int(env.get('DIGEST_HOUR_UTC', '12'))
    if datetime.now(timezone.utc).hour >= hour and state.get('digest_day') != today:
        if state.get('digest_day') is not None:
            snap = usage()
            uso = ('\n\n' + format_usage(snap, state.get('usage_peak'), '📊 Uso nas últimas 24 h')) if snap else ''
            send(env, daily_summary(state) + uso)
        state['digest_day'] = today
        state['daily'] = {}
        state['daily_ips'] = []
        state['usage_peak'] = {'online': 0, 'hora': None}

    save_state(STATE_PATH, state)
    return 0


if __name__ == '__main__':
    sys.exit(run(test='--teste' in sys.argv))
