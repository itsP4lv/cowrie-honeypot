#!/bin/sh
# Installe le service qui applique les bans du panel au pare-feu de l'hôte.
# À lancer en root depuis le dossier du repo : sh host/install.sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p bans
[ -f bans/allowlist.txt ] || printf '# Une IP par ligne : ces IP ne seront jamais bannies (ex : ton IP perso)\n' > bans/allowlist.txt
chown -R 10001 bans  # le panel tourne sous l utilisateur 10001 (non-root) et doit pouvoir écrire la liste
install -m 755 host/honeypot-bans.py /usr/local/sbin/honeypot-bans.py
install -m 644 host/honeypot-bans.service host/honeypot-bans.path /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now honeypot-bans.path
systemctl enable honeypot-bans.service
systemctl start honeypot-bans.service
nft list table inet honeypot_ban
echo "OK : service de ban installé"
