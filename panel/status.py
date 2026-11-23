"""Page de statut : vérifie régulièrement des sites web et des ports TCP.

Les vérifications sont faites par le serveur (pas par le navigateur), toutes les
CHECK_EVERY secondes, et l'historique des dernières 24 h est gardé dans /state.

Cibles : variable STATUS_SITES (dans .env), au format
    Nom|https://exemple.fr;Autre nom|https://autre.fr/page;Port SSH|tcp://hote:22
Les ports des honeypots (Cowrie SSH/Telnet, Redis) sont toujours ajoutés.
La liste est fixée par l'administrateur : la page ne peut pas demander d'URL arbitraire.
"""
import json
import os
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

STATE = os.environ.get("PANEL_STATE", "/state")
HISTORY_FILE = os.path.join(STATE, "status.json")
CHECK_EVERY = 60          # secondes entre deux vérifications
TIMEOUT = 10              # secondes avant de considérer une cible hors ligne
SLOW_MS = 3000            # au-delà : « lent »
KEEP = 24 * 3600          # historique conservé
CERT_EVERY = 6 * 3600     # le certificat TLS est relu toutes les 6 h
UA = "Mozilla/5.0 (compatible; honeypot-status/1.0)"

DEFAULT_TARGETS = "Honeypot SSH|tcp://cowrie:2222;Honeypot Telnet|tcp://cowrie:2223;Honeypot Redis|tcp://redis-hp:6379"


def _parse_targets():
    raw = ";".join(v for v in (os.environ.get("STATUS_SITES", ""), DEFAULT_TARGETS) if v.strip())
    targets, seen = [], set()
    for part in raw.split(";"):
        name, _, url = part.strip().partition("|")
        name, url = name.strip(), url.strip()
        if not url:
            name, url = "", name
        u = urlsplit(url)
        if u.scheme not in ("http", "https", "tcp") or not u.hostname or url in seen:
            continue
        seen.add(url)
        targets.append({"id": str(len(targets)), "name": name or u.hostname, "url": url,
                        "kind": "tcp" if u.scheme == "tcp" else "http"})
    return targets


TARGETS = _parse_targets()
_lock = threading.Lock()
_history = {t["url"]: [] for t in TARGETS}   # url -> [[ts, état, ms], ...]
_last = {}                                    # url -> dernier résultat détaillé
_certs = {}                                   # hôte -> {"t": ..., "days": ..., "error": ...}


# ---------- Vérifications ----------
def _check_http(url):
    t0 = time.monotonic()
    try:
        with urlopen(Request(url, headers={"User-Agent": UA}), timeout=TIMEOUT) as r:
            r.read(65536)
            code = r.status
    except HTTPError as e:
        code = e.code
    ms = round((time.monotonic() - t0) * 1000)
    if code >= 500:
        return "down", ms, code, f"Erreur serveur {code}"
    if code >= 400:
        return "slow", ms, code, f"Réponse {code}"
    return ("slow" if ms > SLOW_MS else "up"), ms, code, ""


def _check_tcp(url):
    u = urlsplit(url)
    t0 = time.monotonic()
    with socket.create_connection((u.hostname, u.port or 80), timeout=TIMEOUT):
        pass
    ms = round((time.monotonic() - t0) * 1000)
    return ("slow" if ms > SLOW_MS else "up"), ms, None, ""


def _cert_days(host, port):
    now = time.time()
    c = _certs.get(host)
    if c and now - c["t"] < CERT_EVERY:
        return c
    c = {"t": now, "days": None, "error": ""}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as s, ctx.wrap_socket(s, server_hostname=host) as tls:
            not_after = ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"])
        c["days"] = int((not_after - now) // 86400)
    except (OSError, ssl.SSLError, KeyError, ValueError) as e:
        c["error"] = str(e)[:120]
    _certs[host] = c
    return c


def _short_error(e):
    if isinstance(e, (socket.timeout, TimeoutError)):
        return "Délai dépassé"
    reason = getattr(e, "reason", e)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "Certificat TLS invalide"
    if isinstance(reason, socket.gaierror):
        return "Nom de domaine introuvable"
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return "Délai dépassé"
    if isinstance(reason, ConnectionRefusedError):
        return "Connexion refusée"
    return str(reason)[:120] or e.__class__.__name__


def _check(t):
    res = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "code": None, "ms": None,
           "error": "", "cert_days": None}
    try:
        state, ms, code, err = (_check_tcp if t["kind"] == "tcp" else _check_http)(t["url"])
        res.update(state=state, ms=ms, code=code, error=err)
    except Exception as e:  # noqa: BLE001 : toute erreur réseau = hors ligne
        res.update(state="down", error=_short_error(e))
    u = urlsplit(t["url"])
    if u.scheme == "https":
        res["cert_days"] = _cert_days(u.hostname, u.port or 443)["days"]
    return res


def check_all():
    if not TARGETS:
        return
    with ThreadPoolExecutor(max_workers=min(8, len(TARGETS))) as pool:
        results = list(pool.map(_check, TARGETS))
    now = time.time()
    with _lock:
        for t, r in zip(TARGETS, results):
            _last[t["url"]] = r
            h = _history.setdefault(t["url"], [])
            h.append([round(now), r["state"], r["ms"]])
            while h and now - h[0][0] > KEEP:
                h.pop(0)
        snapshot = json.dumps(_history)
    try:
        os.makedirs(STATE, exist_ok=True)
        tmp = HISTORY_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(snapshot)
        os.replace(tmp, HISTORY_FILE)
    except OSError:
        pass


def _load():
    try:
        with open(HISTORY_FILE, encoding="utf-8") as f:
            saved = json.load(f)
    except (OSError, ValueError):
        return
    now = time.time()
    with _lock:
        for url in _history:
            _history[url] = [p for p in saved.get(url, []) if isinstance(p, list) and len(p) == 3 and now - p[0] <= KEEP]


def _loop():
    _load()
    while True:
        t0 = time.monotonic()
        try:
            check_all()
        except Exception as e:  # noqa: BLE001 : la boucle ne doit jamais s'arrêter
            print("status:", e, flush=True)
        time.sleep(max(5, CHECK_EVERY - (time.monotonic() - t0)))


def start():
    threading.Thread(target=_loop, daemon=True, name="status").start()


# ---------- Vue pour la page ----------
BUCKETS = 48  # barres de 30 min sur 24 h
RANK = {"up": 0, "slow": 1, "down": 2}


def view():
    now = time.time()
    size = KEEP / BUCKETS
    out = []
    with _lock:
        for t in TARGETS:
            h = list(_history.get(t["url"], []))
            last = dict(_last.get(t["url"]) or {})
            bars = [None] * BUCKETS
            for ts, st, _ms in h:
                i = int((ts - (now - KEEP)) // size)
                if 0 <= i < BUCKETS:
                    bars[i] = st if bars[i] is None or RANK.get(st, 2) > RANK.get(bars[i], 2) else bars[i]
            ok = sum(1 for p in h if p[1] != "down")
            u = urlsplit(t["url"])
            out.append({
                "id": t["id"], "name": t["name"], "kind": t["kind"],
                "host": u.hostname + (u.path if u.path not in ("", "/") else ""),
                "link": t["url"] if t["kind"] == "http" else "",
                "state": last.get("state", "pending"), "ms": last.get("ms"), "code": last.get("code"),
                "error": last.get("error", ""), "checked": last.get("ts", ""), "cert_days": last.get("cert_days"),
                "uptime": round(100 * ok / len(h), 2) if h else None,
                "bars": bars,
                "latency": [p[2] for p in h[-60:]],
            })
    return {"interval": CHECK_EVERY, "targets": out}


def summary():
    v = view()["targets"]
    count = lambda s: sum(1 for t in v if t["state"] == s)  # noqa: E731
    return {"total": len(v), "up": count("up"), "slow": count("slow"), "down": count("down"),
            "pending": count("pending"), "targets": [{"name": t["name"], "state": t["state"]} for t in v]}
