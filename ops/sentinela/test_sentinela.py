"""Testes do sentinela: python -m unittest ops/sentinela/test_sentinela.py"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import sentinela as s  # noqa: E402


def caddy(uri, status, ip='1.2.3.4'):
    return json.dumps({'request': {'client_ip': ip, 'uri': uri, 'method': 'GET'}, 'status': status})


SNAP = {
    'membros': 120, 'fundadores': 30, 'cadastros_1h': 2, 'cadastros_24h': 9, 'cadastros_7d': 31,
    'sem_onboarding_7d': 4, 'ativos_24h': 40, 'ativos_7d': 60, 'online_agora': 7, 'em_foco_agora': 3,
    'foco_min_24h': 135, 'foco_pessoas_24h': 5, 'foco_sessoes_24h': 8, 'aulas_concluidas_24h': 12,
    'alunos_24h': 6, 'posts_24h': 3, 'comentarios_24h': 10, 'curtidas_24h': 22, 'xp_24h': 640,
    'top_foco_24h': [{'username': 'beto', 'min': 90}, {'username': 'ana', 'min': 30}],
    'aula_top_24h': {'titulo': 'Spec Kit · Parte 1/13', 'vezes': 4},
}


class Uso(unittest.TestCase):
    def test_resumo_legivel_com_os_numeros(self):
        txt = s.format_usage(SNAP, {'online': 9, 'hora': '21:10'})
        self.assertIn('online agora: 7 (3 em foco)', txt)
        self.assertIn('pico de online: 9 às 21:10', txt)
        self.assertIn('2h 15min', txt)
        self.assertIn('4 pararam antes de terminar o cadastro', txt)
        self.assertIn('@beto (90 min)', txt)
        self.assertIn('Spec Kit · Parte 1/13 (4×)', txt)
        self.assertIn('50% dos membros apareceram na semana', txt)

    def test_snapshot_vazio_nao_quebra(self):
        self.assertIn('online agora: 0 (0 em foco)', s.format_usage({}))

    def test_pico_do_dia_e_recorde(self):
        st = {}
        self.assertEqual(s.track_usage({'online_agora': 6}, st, 1_000_000), [])  # 1ª leitura só registra
        self.assertEqual(st['usage_peak']['online'], 6)
        alerts = s.track_usage({'online_agora': 8, 'em_foco_agora': 2}, st, 1_000_600)
        self.assertTrue(any('Recorde' in a and '8' in a for a in alerts))
        self.assertEqual(s.track_usage({'online_agora': 3}, st, 1_001_200), [])
        self.assertEqual(st['usage_peak']['online'], 8)

    def test_rajada_de_cadastro_alerta_uma_vez(self):
        st = {}
        a1 = s.track_usage({'cadastros_1h': 20}, st, 2_000_000)
        a2 = s.track_usage({'cadastros_1h': 25}, st, 2_000_600)
        self.assertEqual(sum('cadastros na última hora' in a for a in a1), 1)
        self.assertEqual(a2, [])

    def test_comandos_so_do_chat_do_dono(self):
        ups = [
            {'update_id': 10, 'message': {'chat': {'id': 999}, 'text': '/status'}},
            {'update_id': 11, 'message': {'chat': {'id': 123}, 'text': '/status@GuildaBot'}},
            {'update_id': 12, 'message': {'chat': {'id': 123}, 'text': 'oi'}},
            {'update_id': 13, 'message': {'chat': {'id': 123}, 'text': '/ajuda'}},
        ]
        cmds, last = s.parse_commands(ups, '123')
        self.assertEqual(cmds, ['status', 'ajuda'])
        self.assertEqual(last, 13)


class Caddy(unittest.TestCase):
    def test_sondas_contam_e_trafego_normal_nao(self):
        r = s.analyze_caddy([
            caddy('/.env', 404), caddy('/wp-login.php', 404), caddy('/.git/config', 404),
            caddy('/perfil', 200), caddy('/c/tecnologia/post', 200), caddy('/images/x.png', 200),
            'linha quebrada',
        ])
        self.assertEqual(r['scanner']['1.2.3.4'], 3)
        self.assertEqual(r['scanner_ok'], [])

    def test_redirect_pro_login_nao_e_exposicao(self):
        # Caso real (2026-10-20): robô pede /wp-admin/install.php, o gate manda
        # pro /login?next=/wp-admin/..., e o /login responde 200. Não é exposição.
        r = s.analyze_caddy([
            caddy('/wp-admin/install.php', 307, '7.7.7.7'),
            caddy('/login?step=1&next=%2Fwp-admin%2Finstall.php', 200, '7.7.7.7'),
        ])
        self.assertEqual(r['scanner_ok'], [])
        self.assertEqual(r['scanner']['7.7.7.7'], 1)

    def test_ataque_na_query_conta_como_sonda_mas_nunca_como_exposicao(self):
        r = s.analyze_caddy([caddy('/c?q=1%20union%20select%20senha', 200, '8.8.8.8')])
        self.assertEqual(r['scanner']['8.8.8.8'], 1)
        self.assertEqual(r['scanner_ok'], [])

    def test_sonda_respondida_com_200_vira_exposicao(self):
        r = s.analyze_caddy([caddy('/.env', 200, '9.9.9.9')])
        self.assertEqual(r['scanner_ok'], [('9.9.9.9', '/.env', 200)])

    def test_forca_bruta_e_limite(self):
        r = s.analyze_caddy([caddy('/api/me', 401)] * 3 + [caddy('/login', 429)] * 2 + [caddy('/c', 403)])
        self.assertEqual(r['auth_fail']['1.2.3.4'], 3)  # /c não é rota de login/API
        self.assertEqual(r['rate_limited']['1.2.3.4'], 2)


class Ssh(unittest.TestCase):
    LINES = [
        'Oct 20 10:00:00 vps sshd[1]: Accepted publickey for root from 189.4.120.249 port 51000 ssh2',
        'Oct 20 10:01:00 vps sshd[2]: Accepted password for root from 45.9.9.9 port 2222 ssh2',
        'Oct 20 10:02:00 vps sshd[3]: Failed password for root from 5.5.5.5 port 1 ssh2',
        'Oct 20 10:02:01 vps sshd[3]: Failed password for invalid user admin from 5.5.5.5 port 1 ssh2',
        'Oct 20 10:02:02 vps sshd[4]: Invalid user oracle from 6.6.6.6 port 2',
    ]

    def test_login_aceito_fora_da_lista_e_falhas(self):
        r = s.analyze_ssh(self.LINES, {'189.4.120.249'})
        self.assertEqual(r['accepted_unknown'], [('root', '45.9.9.9', 'password')])
        self.assertEqual(r['failures']['5.5.5.5'], 2)
        self.assertEqual(r['failures']['6.6.6.6'], 1)


class Alertas(unittest.TestCase):
    def test_rajada_alerta_uma_vez_por_janela(self):
        state = {}
        c = s.analyze_caddy([caddy('/.env', 404)] * 6)
        ssh = s.analyze_ssh([], set())
        self.assertEqual(len(s.build_alerts(c, ssh, state, 1000)), 1)
        self.assertEqual(len(s.build_alerts(c, ssh, state, 1000 + 60)), 0)  # cooldown
        self.assertEqual(len(s.build_alerts(c, ssh, state, 1000 + s.COOLDOWN_S + 1)), 1)

    def test_poucas_sondas_nao_alertam_mas_entram_no_resumo(self):
        state = {}
        c = s.analyze_caddy([caddy('/.env', 404)] * 2)
        ssh = s.analyze_ssh(Ssh.LINES[2:], set())
        self.assertEqual(s.build_alerts(c, ssh, state, 0), [])
        s.add_to_daily(state, c, ssh)
        texto = s.daily_summary(state)
        self.assertIn('5 tentativas de invasão', texto)
        self.assertIn('senhas erradas no SSH: 3', texto)

    def test_login_desconhecido_sempre_alerta(self):
        a = s.build_alerts(s.analyze_caddy([]), s.analyze_ssh(Ssh.LINES, {'189.4.120.249'}), {}, 0)
        self.assertTrue(any('LOGIN NO SERVIDOR' in x and '45.9.9.9' in x for x in a))


if __name__ == '__main__':
    unittest.main()
