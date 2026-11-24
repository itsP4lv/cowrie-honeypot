"""Ban automatique des IP qui envoient des commandes en rafale.

Une IP qui tape plus de AUTOBAN_COMMANDS commandes en AUTOBAN_WINDOW secondes
(toutes sessions confondues) est ajoutée à la liste des bans, comme avec le bouton
« Bannir ». Le ban expire au bout de AUTOBAN_HOURS heures (0 = définitif).

Seuls les événements « en direct » comptent : le rattrapage des anciens logs au
démarrage du panel ne bannit personne. Les garde-fous du service de l'hôte
(IP privée, allowlist, session SSH d'admin) s'appliquent toujours.
"""
import ipaddress
import os
import threading
import time
from collections import deque
from datetime import datetime


def _int(name, default, lo, hi):
    try:
        return min(hi, max(lo, int(os.environ.get(name, default))))
    except ValueError:
        return default


ENABLED = os.environ.get("AUTOBAN_ENABLED", "true").strip().lower() in ("1", "true", "yes", "on")
COMMANDS = _int("AUTOBAN_COMMANDS", 30, 5, 10000)
WINDOW = _int("AUTOBAN_WINDOW", 60, 5, 86400)
HOURS = _int("AUTOBAN_HOURS", 24, 0, 24 * 365)

_hits = {}  # ip -> horodatages (secondes) des dernières commandes
_lock = threading.Lock()
_ban = None  # fonction (ip, reason, hours) fournie par app.py
_notify = None  # fonction (texte) pour prévenir sur Discord/Telegram


def setup(ban, notify=None):
    global _ban, _notify
    _ban, _notify = ban, notify


def describe():
    if not ENABLED:
        return ""
    return f"{COMMANDS} commandes en {WINDOW} s → ban " + (f"{HOURS} h" if HOURS else "définitif")


def on_event(ev):
    if not ENABLED or _ban is None or ev.get("kind") != "command":
        return
    try:
        ip = str(ipaddress.ip_address(ev.get("ip") or ""))
    except ValueError:
        return
    if not ipaddress.ip_address(ip).is_global:
        return
    try:  # heure de l'événement dans le log, pour ne pas fausser le comptage si le panel lit en retard
        now = datetime.fromisoformat(str(ev.get("ts")).replace("Z", "+00:00")).timestamp()
    except ValueError:
        now = time.time()
    with _lock:
        q = _hits.setdefault(ip, deque())
        q.append(now)
        while q and now - q[0] > WINDOW:
            q.popleft()
        if len(q) <= COMMANDS:
            if len(_hits) > 20000:  # nettoyage : IP silencieuses depuis plus d'une fenêtre
                for k in [k for k, v in _hits.items() if not v or now - v[-1] > WINDOW]:
                    del _hits[k]
            return
        n = len(q)
        del _hits[ip]
    reason = f"ban auto : {n} commandes en moins de {WINDOW} s"
    if _ban(ip, reason, HOURS) and _notify:
        dur = f"pour {HOURS} h" if HOURS else "définitivement"
        _notify(f"🚫 [{ev.get('sensor', '?')}] IP bannie automatiquement {dur}\n{ip}\n{reason}")
