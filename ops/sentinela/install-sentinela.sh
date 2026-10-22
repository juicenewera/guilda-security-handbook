#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

[[ "$(id -u)" -eq 0 ]] || { echo 'execute como root' >&2; exit 1; }
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

install -d -m 700 /opt/guilda-sentinela /var/lib/guilda-sentinela
install -m 700 "$source_dir/sentinela.py" /opt/guilda-sentinela/sentinela.py
install -m 644 "$source_dir/guilda-sentinela.service" /etc/systemd/system/guilda-sentinela.service
install -m 644 "$source_dir/guilda-sentinela.timer" /etc/systemd/system/guilda-sentinela.timer

if [[ ! -e /opt/guilda-sentinela/sentinela.env ]]; then
  install -m 600 "$source_dir/sentinela.env.example" /opt/guilda-sentinela/sentinela.env
  echo 'Arquivo criado: /opt/guilda-sentinela/sentinela.env (preencha token e chat ID antes de ativar)'
fi

systemctl daemon-reload
systemctl enable guilda-sentinela.timer
echo 'Sentinela instalado. Depois de configurar o env, execute:'
echo '  systemctl start guilda-sentinela.timer'
echo '  systemctl start guilda-sentinela.service'
echo '  python3 /opt/guilda-sentinela/sentinela.py --teste'
