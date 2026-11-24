"""Classement automatique des commandes tapées par les attaquants.

Chaque règle est une expression régulière appliquée aux commandes d'une session.
Une session peut avoir plusieurs étiquettes. Pour en ajouter : une ligne dans RULES.
"""
import re

# (identifiant, libellé affiché, expression régulière)
RULES = [
    ("detect", "Détection de honeypot",
     r"check_[0-9a-f]{16,}|/proc/self/(stat|status)|\bhoneypot\b|cowrie|echo\s+-e\s+[\"']\\x"),
    ("miner", "Mineur de crypto",
     r"xmrig|minerd|cpuminer|stratum\+(tcp|ssl)|cryptonight|nicehash|monero|c3pool|supportxmr|kdevtmpfsi|kinsing|\.xmr\b"),
    ("botnet", "Botnet (Mirai…)",
     r"mirai|gafgyt|tsunami|/bin/busybox\s+[A-Z]{4,}|\bbins\.sh\b|\.(arm7?|mips|mpsl|x86|i686)\b"),
    ("download", "Téléchargement de payload",
     r"\b(wget|curl|tftp|ftpget|lwp-download|fetch)\b[^|;]*?(https?|ftp)://|/dev/tcp/\d|busybox\s+(wget|tftp)"),
    ("exec", "Exécution de binaire",
     r"chmod\s+(\+x|[0-7]*[1357][0-7]*\s)|(^|[;&|]\s*)\./[\w.-]+|\b(sh|bash)\s+[\w./-]+\.sh\b"),
    ("persist", "Persistance",
     r"authorized_keys|crontab|/etc/cron|rc\.local|systemctl\s+enable|/etc/init\.d|/etc/systemd/system|\.bashrc|\.profile"),
    ("accounts", "Comptes / mots de passe",
     r"\b(passwd|chpasswd|useradd|adduser|usermod|userdel)\b|/etc/shadow"),
    ("cleanup", "Effacement de traces",
     r"history\s+-c|unset\s+HISTFILE|HISTSIZE=0|rm\s+-rf?\s+(/var/log|~/\.bash_history)|\bshred\b"),
    ("redis", "Attaque Redis",
     r"^\s*(slaveof|replicaof|module\s+load|config\s+set\s+(dir|dbfilename)|flushall)\b"),
    ("recon", "Reconnaissance",
     r"\buname\b|/proc/cpuinfo|\bnproc\b|\blscpu\b|\bfree\b|/etc/os-release|\bwhoami\b|^\s*id\s*$|\bifconfig\b|\bip\s+a|\buptime\b|\bdf\b|/etc/passwd|\bw\s*$|\bps\s"),
]
_COMPILED = [(tid, re.compile(rx, re.I | re.M)) for tid, _, rx in RULES]
LABELS = {tid: label for tid, label, _ in RULES}


def classify(command):
    """Renvoie l'ensemble des étiquettes d'une commande."""
    if not command:
        return set()
    return {tid for tid, rx in _COMPILED if rx.search(command)}
