"""Alertes Discord / Telegram (optionnelles, configurées dans .env).

Les messages contiennent des données envoyées par les attaquants (identifiants,
commandes, URL). On les nettoie : caractères de contrôle retirés, longueur bornée,
aucune mention Discord possible (@everyone…), pas de mise en forme Telegram.
Anti-spam : une même alerte (type + IP) au plus toutes les 30 min, et 30 alertes/heure max.
"""
import json
import os
import queue
import re
import threading
import time
import urllib.request

from geoip import geo

DISCORD = os.environ.get("ALERT_DISCORD_WEBHOOK", "").strip()
TG_TOKEN = os.environ.get("ALERT_TELEGRAM_TOKEN", "").strip()
TG_CHAT = os.environ.get("ALERT_TELEGRAM_CHAT", "").strip()
EVENTS = {e.strip() for e in os.environ.get("ALERT_EVENTS", "login,file,country").split(",") if e.strip()}

if DISCORD and not re.fullmatch(r"https://(discord|discordapp)\.com/api/webhooks/\d+/[\w-]+", DISCORD):
    print("alertes : ALERT_DISCORD_WEBHOOK invalide, ignoré", flush=True)
    DISCORD = ""
if TG_TOKEN and not re.fullmatch(r"\d+:[\w-]{30,}", TG_TOKEN):
    print("alertes : ALERT_TELEGRAM_TOKEN invalide, ignoré", flush=True)
    TG_TOKEN = ""
if TG_CHAT and not re.fullmatch(r"-?\d+|@\w{4,}", TG_CHAT):
    TG_CHAT = ""

CHANNELS = [n for n, ok in (("Discord", DISCORD), ("Telegram", TG_TOKEN and TG_CHAT)) if ok]
DEDUP_SECONDS = 1800
MAX_PER_HOUR = 30

_q = queue.Queue(maxsize=200)
_last = {}
_sent = []
_seen_countries = set()
_lock = threading.Lock()


def clean(v, n=150):
    s = re.sub(r"[\x00-\x1f\x7f]", " ", str(v or ""))
    s = s.replace("`", "'").replace("@", "@​")  # pas de bloc de code cassé ni de mention
    return s[:n] + ("…" if len(s) > n else "")


def _post(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": "honeypot-panel"})
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read()


def _send(text):
    if DISCORD:
        try:
            _post(DISCORD, {"content": text[:1900], "allowed_mentions": {"parse": []}})
        except Exception as exc:  # noqa: BLE001
            print("alerte Discord :", exc, flush=True)
    if TG_TOKEN and TG_CHAT:
        try:
            _post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                  {"chat_id": TG_CHAT, "text": text[:3500], "disable_web_page_preview": True})
        except Exception as exc:  # noqa: BLE001
            # le token est dans l'URL : on n'affiche que le type d'erreur
            print("alerte Telegram :", type(exc).__name__, flush=True)


def _worker():
    while True:
        text = _q.get()
        _send(text)


def start():
    if CHANNELS:
        threading.Thread(target=_worker, daemon=True, name="alerts").start()


def _allow(key):
    now = time.time()
    with _lock:
        if now - _last.get(key, 0) < DEDUP_SECONDS:
            return False
        _sent[:] = [t for t in _sent if now - t < 3600]
        if len(_sent) >= MAX_PER_HOUR:
            return False
        _last[key] = now
        _sent.append(now)
        return True


def queue_text(text):
    try:
        _q.put_nowait(text)
    except queue.Full:
        pass


def seed_countries(ccs):
    _seen_countries.update(c for c in ccs if c)


def where(ip):
    g = geo(ip)
    place = ", ".join(x for x in (g["city"], g["country"]) if x) or "localisation inconnue"
    org = f" · AS{g['asn']} {g['org']}" if g["asn"] else ""
    return g, f"{ip} ({place}{org})"


def on_event(ev):
    """Appelé par l'ingestion pour chaque nouvel événement."""
    if not CHANNELS or not ev.get("ip"):
        return
    ip, kind, sensor = ev["ip"], ev["kind"], ev.get("sensor", "?")
    if kind == "login_ok" and "login" in EVENTS and _allow(("login", ip)):
        _, w = where(ip)
        queue_text(f"🔓 [{sensor}] Login réussi\n{w}\nidentifiants : {clean(ev.get('username'), 60)} / {clean(ev.get('password'), 60)}")
    elif kind == "file" and "file" in EVENTS and _allow(("file", ip, ev.get("shasum"))):
        _, w = where(ip)
        queue_text(f"📦 [{sensor}] Fichier capturé\n{w}\nsource : {clean(ev.get('url'), 200)}\nSHA-256 : {clean(ev.get('shasum'), 64)}")
    elif kind == "connect" and "country" in EVENTS:
        g, w = where(ip)
        cc = g["cc"]
        if cc and cc not in _seen_countries:
            _seen_countries.add(cc)
            if _allow(("country", cc)):
                queue_text(f"🌍 [{sensor}] Premier visiteur de ce pays : {g['country'] or cc.upper()}\n{w}")


def test_message():
    queue_text("✅ Test des alertes du panel honeypot : la configuration fonctionne.")
