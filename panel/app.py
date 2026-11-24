"""Panel web des honeypots (Cowrie aujourd'hui, d'autres demain).

- store.py   : ingestion des logs au fil de l'eau dans SQLite + requêtes
- geoip.py   : géolocalisation hors ligne (DB-IP Lite)
- tags.py    : classement automatique des commandes (mineur, botnet, persistance…)
- alerts.py  : alertes Discord / Telegram (optionnelles)
- vt.py      : réputation VirusTotal des fichiers capturés, par hash (optionnelle)
- tty.py     : relecture des sessions enregistrées par Cowrie
- status.py  : page de statut (sites web et ports surveillés par le serveur)
- soc.py     : vue SOC (bilan depuis la mise en ligne, menace, incidents)
- static/    : la page (HTML/CSS/JS sans framework)

Toutes les données affichées viennent des attaquants : la page les insère avec
textContent (jamais innerHTML) pour éviter toute XSS, et une CSP stricte interdit
tout script qui ne vient pas du panel.
"""
import ipaddress
import json
import os
import threading
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from flask import Flask, abort, g, jsonify, request, send_from_directory

import alerts
import autoban
import geoip
import soc
import status
import store
import tags
import tty
import vt
from geoip import geo

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")
DOWNLOADS = os.path.join(store.DATA, "lib", "cowrie", "downloads")
MAX_IPS = 1500  # IP les plus récentes envoyées au navigateur (tableau + carte)
# Bans : le panel écrit la liste, un service systemd sur l'hôte l'applique au pare-feu
# (le conteneur n'a aucun droit sur le réseau de l'hôte). Voir host/.
BANS_DIR = os.environ.get("PANEL_BANS", "/bans")
BANLIST = os.path.join(BANS_DIR, "banlist.json")
APPLIED = os.path.join(BANS_DIR, "applied.json")
# Noms d'hôte acceptés dans l'en-tête Host (protection contre le DNS rebinding).
ALLOWED_HOSTS = {h.strip() for h in os.environ.get("PANEL_ALLOWED_HOSTS", "localhost,127.0.0.1,::1").split(",") if h.strip()}

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


# ---------- Sécurité HTTP ----------
@app.before_request
def check_host():
    # Un site malveillant qui ferait pointer son domaine sur 127.0.0.1 (DNS rebinding)
    # ne pourrait pas lire le panel à travers le tunnel : son Host serait refusé.
    if urlsplit("//" + (request.host or "")).hostname not in ALLOWED_HOSTS:
        abort(403)


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def check_csrf():
    """Le panel n'a pas de mot de passe (il est derrière un tunnel SSH). Pour qu'un site
    ouvert dans le navigateur ne puisse rien déclencher via le tunnel :
    Origin (s'il est présent) identique à Host, et en-tête personnalisé + JSON, impossibles
    à envoyer depuis un autre site sans requête CORS préalable, que le panel ne valide jamais."""
    origin = request.headers.get("Origin")
    if origin and urlsplit(origin).netloc != request.host:
        abort(403)
    if request.headers.get("X-Panel") != "1" or not request.is_json:
        abort(403)


def db():
    if "db" not in g:
        g.db = store.connect(readonly=True)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    con = g.pop("db", None)
    if con is not None:
        con.close()


def ready_or_503():
    if not INGESTER.ready.is_set():
        abort(503, "Import des logs en cours, réessaie dans quelques secondes")


# ---------- Bans ----------
_ban_lock = threading.Lock()


def _read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write_banlist(bans):
    os.makedirs(BANS_DIR, exist_ok=True)
    tmp = BANLIST + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(bans, f, indent=1, sort_keys=True)
    os.replace(tmp, BANLIST)  # écriture atomique : le service ne lit jamais un fichier à moitié écrit


def bans_view():
    bans = _read_json(BANLIST, {})
    applied = _read_json(APPLIED, {})
    done, skipped = set(applied.get("applied", [])), applied.get("skipped", {})
    try:
        list_mtime = os.path.getmtime(BANLIST)
    except OSError:
        list_mtime = 0
    helper_ts = applied.get("ts", 0)
    rows = []
    for ip, info in bans.items():
        gi = geo(ip)
        if ip in skipped:
            st, detail = "refuse", str(skipped[ip])
        elif ip in done:
            st, detail = "actif", ""
        else:
            st, detail = "attente", ""
        rows.append({"ip": ip, "ts": info.get("ts", ""), "reason": info.get("reason", ""),
                     "auto": bool(info.get("auto")), "expires": info.get("expires", ""),
                     "cc": gi["cc"], "country": gi["country"], "status": st, "detail": detail})
    rows.sort(key=lambda r: r["ts"], reverse=True)
    return {"list": rows, "helper_ts": helper_ts, "helper_error": applied.get("error", ""),
            "helper_late": bool(bans) and list_mtime - helper_ts > 30 and time.time() - list_mtime > 30}


def _valid_public_ip(raw):
    try:
        addr = ipaddress.ip_address(str(raw))
    except ValueError:
        abort(400, "IP invalide")
    if not addr.is_global:
        abort(400, "IP privée ou réservée : pas de ban")
    return str(addr)


@app.post("/api/bans")
def ban_ip():
    check_csrf()
    body = request.get_json(silent=True) or {}
    ip = _valid_public_ip(body.get("ip"))
    reason = str(body.get("reason", ""))[:200]
    with _ban_lock:
        bans = _read_json(BANLIST, {})
        bans[ip] = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "reason": reason}
        _write_banlist(bans)
    return jsonify(bans_view())


def auto_ban(ip, reason, hours):
    """Appelé par autoban.py. Ne touche pas une IP déjà bannie (manuellement ou non)."""
    now = datetime.now(timezone.utc)
    entry = {"ts": now.isoformat(timespec="seconds"), "reason": reason[:200], "auto": True}
    if hours:
        entry["expires"] = (now + timedelta(hours=hours)).isoformat(timespec="seconds")
    with _ban_lock:
        bans = _read_json(BANLIST, {})
        if ip in bans:
            return False
        bans[ip] = entry
        _write_banlist(bans)
    print(f"autoban : {ip} ({reason})", flush=True)
    return True


def _expire_bans():
    """Retire les bans automatiques arrivés à expiration (les bans manuels restent)."""
    while True:
        time.sleep(60)
        try:
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            with _ban_lock:
                bans = _read_json(BANLIST, {})
                old = [ip for ip, b in bans.items() if b.get("expires") and b["expires"] <= now]
                if old:
                    for ip in old:
                        del bans[ip]
                    _write_banlist(bans)
                    print("autoban : expiré", ", ".join(old), flush=True)
        except Exception as exc:  # noqa: BLE001
            print("autoban :", exc, flush=True)


def _notify_ban(text):
    if alerts.CHANNELS and alerts._allow(("autoban", text)):
        alerts.queue_text(text)


@app.delete("/api/bans/<path:ip>")
def unban_ip(ip):
    check_csrf()
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        abort(400)
    with _ban_lock:
        bans = _read_json(BANLIST, {})
        if bans.pop(ip, None) is not None:
            _write_banlist(bans)
    return jsonify(bans_view())


# ---------- Tableau de bord ----------
_stats_cache = {"t": 0, "data": None}
_stats_lock = threading.Lock()


def vt_map(con, shas):
    shas = [s.lower() for s in shas if s]
    if not shas:
        return {}
    q = f"SELECT * FROM vt WHERE sha256 IN ({','.join('?' * len(shas))})"
    return {r["sha256"]: {"status": r["status"], "malicious": r["malicious"], "total": r["total"], "label": r["label"]}
            for r in con.execute(q, shas)}


def compute_stats(con):
    one = lambda sql, a=(): con.execute(sql, a).fetchone()[0]  # noqa: E731
    totals = {
        "connexions": one("SELECT COUNT(*) FROM events WHERE kind='connect'"),
        "ips_uniques": one("SELECT COUNT(DISTINCT ip) FROM events WHERE kind='connect'"),
        "tentatives": one(f"SELECT COUNT(*) FROM events WHERE kind IN {store.LOGIN_KINDS}"),
        "reussies": one("SELECT COUNT(*) FROM events WHERE kind='login_ok'"),
        "commandes": one("SELECT COUNT(*) FROM events WHERE kind='command'"),
    }
    try:
        totals["fichiers"] = len([f for f in os.listdir(DOWNLOADS) if not f.startswith(".")])
    except OSError:
        totals["fichiers"] = 0

    # IP : géoloc + compteurs + étiquettes
    all_ips = [dict(r) for r in con.execute(
        "SELECT ip, SUM(kind='connect') AS connexions FROM events WHERE ip IS NOT NULL GROUP BY ip")]
    countries = {}
    for r in all_ips:
        gi = geo(r["ip"])
        if not gi["cc"]:
            continue
        c = countries.setdefault(gi["cc"], {"cc": gi["cc"], "country": gi["country"], "ips": 0, "connexions": 0})
        c["ips"] += 1
        c["connexions"] += r["connexions"]
    totals["pays"] = len(countries)
    recent = store.ip_summaries(con, limit=MAX_IPS)
    tg = store.tags_by_ip(con, (r["ip"] for r in recent))
    for r in recent:
        r.update(geo(r["ip"]))
        r["tags"] = tg.get(r["ip"], [])
    cc_of = lambda ip: geo(ip)["cc"] if ip else ""  # noqa: E731

    top_ips = store.top(con, "SELECT ip, COUNT(*) c FROM events WHERE kind='connect' GROUP BY ip ORDER BY c DESC")
    for r in top_ips:
        r["cc"] = cc_of(r["label"])

    # activité 24 h (heure par heure, heures vides comprises) et carte de chaleur 7 jours
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    hours = {r[0]: (r[1], r[2]) for r in con.execute(
        f"""SELECT substr(ts,1,13) h, SUM(kind='connect'), SUM(kind IN {store.LOGIN_KINDS})
            FROM events WHERE ts >= ? GROUP BY h""", (store.since_iso(24 * 7 + 1),))}
    per_hour = []
    for i in range(23, -1, -1):
        b = now - timedelta(hours=i)
        c, t = hours.get(b.strftime("%Y-%m-%dT%H"), (0, 0))
        per_hour.append({"ts": b.isoformat(), "connexions": c, "tentatives": t})
    heatmap = [{"ts": h + ":00:00+00:00", "n": v[0]} for h, v in hours.items() if v[0]]

    top_tags = [{"tag": r["tag"], "label": tags.LABELS.get(r["tag"], r["tag"]), "ips": r["n"], "sessions": r["s"]}
                for r in con.execute("SELECT tag, COUNT(DISTINCT ip) n, COUNT(*) s FROM tags GROUP BY tag ORDER BY n DESC")]

    files = [dict(r) for r in con.execute(
        "SELECT ts, ip, url, shasum AS sha256 FROM events WHERE kind='file' ORDER BY id DESC LIMIT 50")]
    vtm = vt_map(con, [f["sha256"] for f in files])
    for f in files:
        f["cc"] = cc_of(f["ip"])
        f["url"] = f["url"] or ""
        f["sha256"] = f["sha256"] or ""
        f["vt"] = vtm.get(f["sha256"].lower())

    return {
        "totals": totals,
        "geo": geoip.ENABLED,
        "sensors": [r[0] for r in con.execute("SELECT DISTINCT sensor FROM events")],
        "features": {"alerts": alerts.CHANNELS, "virustotal": vt.ENABLED, "autoban": autoban.describe()},
        "top_ips": top_ips,
        "top_countries": sorted(countries.values(), key=lambda c: (-c["ips"], -c["connexions"]))[:10],
        "top_tags": top_tags,
        "ips": recent,
        "ips_total": len(all_ips),
        "top_users": store.top(con, f"SELECT username, COUNT(*) c FROM events WHERE kind IN {store.LOGIN_KINDS} GROUP BY username ORDER BY c DESC"),
        "top_passwords": store.top(con, f"SELECT password, COUNT(*) c FROM events WHERE kind IN {store.LOGIN_KINDS} GROUP BY password ORDER BY c DESC"),
        "top_combos": store.top(con, f"SELECT COALESCE(username,'') || ' / ' || COALESCE(password,''), COUNT(*) c FROM events WHERE kind IN {store.LOGIN_KINDS} GROUP BY 1 ORDER BY c DESC"),
        "top_commands": store.top(con, "SELECT input, COUNT(*) c FROM events WHERE kind='command' GROUP BY input ORDER BY c DESC"),
        "top_clients": store.top(con, "SELECT version, COUNT(*) c FROM events WHERE kind='client' GROUP BY version ORDER BY c DESC"),
        "per_hour": per_hour,
        "heatmap": heatmap,
        "commands": [{"ts": r["ts"], "ip": r["ip"] or "", "cc": cc_of(r["ip"]), "session": r["session"] or "",
                      "input": r["input"] or ""} for r in con.execute(
            "SELECT ts, ip, session, input FROM events WHERE kind='command' ORDER BY id DESC LIMIT 100")],
        "logins": [{"ts": r["ts"], "ip": r["ip"] or "", "cc": cc_of(r["ip"]), "user": r["username"] or "",
                    "password": r["password"] or "", "ok": r["kind"] == "login_ok"} for r in con.execute(
            f"SELECT ts, ip, username, password, kind FROM events WHERE kind IN {store.LOGIN_KINDS} ORDER BY id DESC LIMIT 100")],
        "files": files,
    }


@app.get("/api/stats")
def stats():
    ready_or_503()
    with _stats_lock:  # plusieurs onglets ouverts = un seul calcul toutes les 2 s
        if time.time() - _stats_cache["t"] > 2 or _stats_cache["data"] is None:
            _stats_cache["data"] = compute_stats(db())
            _stats_cache["t"] = time.time()
        data = dict(_stats_cache["data"])
    data["bans"] = bans_view()
    return jsonify(data)


_soc_cache = {"t": 0, "data": None}


@app.get("/api/soc")
def soc_api():
    ready_or_503()
    with _stats_lock:
        if time.time() - _soc_cache["t"] > 10 or _soc_cache["data"] is None:
            _soc_cache["data"] = soc.compute(db(), geo, bans_view()["list"])
            _soc_cache["t"] = time.time()
        return jsonify(_soc_cache["data"])


@app.get("/api/ip/<path:ip>")
def ip_detail(ip):
    """Fiche complète d'une IP : géoloc, sessions, identifiants, commandes, fichiers."""
    ready_or_503()
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        abort(400)
    con = db()
    summary = store.ip_summaries(con, "ip = ?", (ip,))
    if not summary:
        abort(404)
    detail = summary[0]
    detail.update(geo(ip))
    sessions, order = {}, []
    creds, creds_ok, clients, files = Counter(), set(), Counter(), []
    for r in con.execute("SELECT * FROM events WHERE ip = ? ORDER BY id", (ip,)):
        sid = r["session"] or ""
        s = sessions.get(sid)
        if s is None:
            s = sessions[sid] = {"id": sid, "sensor": r["sensor"], "start": r["ts"], "end": r["ts"], "protocol": "",
                                 "port": None, "client": "", "duration": None, "tty": False,
                                 "logins": [], "commands": [], "files": [], "tags": []}
            order.append(sid)
        s["end"] = r["ts"]
        k = r["kind"]
        if k == "connect":
            s["protocol"], s["port"] = r["protocol"] or "", r["dst_port"]
        elif k == "client":
            s["client"] = r["version"] or ""
            clients[s["client"]] += 1
        elif k in ("login_ok", "login_fail"):
            u, p, ok = r["username"] or "", r["password"] or "", k == "login_ok"
            s["logins"].append({"ts": r["ts"], "user": u, "password": p, "ok": ok})
            creds[(u, p)] += 1
            if ok:
                creds_ok.add((u, p))
        elif k == "command":
            s["commands"].append({"ts": r["ts"], "input": r["input"] or ""})
        elif k == "file":
            f = {"ts": r["ts"], "url": r["url"] or "", "sha256": r["shasum"] or ""}
            s["files"].append(f)
            files.append(f)
        elif k == "closed":
            s["duration"] = r["duration"]
        elif k == "tty":
            s["tty"] = tty.path_for(r["ttylog"]) is not None
    for r in con.execute("SELECT session, tag FROM tags WHERE ip = ?", (ip,)):
        if r["session"] in sessions:
            sessions[r["session"]]["tags"].append({"tag": r["tag"], "label": tags.LABELS.get(r["tag"], r["tag"])})
    vtm = vt_map(con, [f["sha256"] for f in files])
    for f in files:
        f["vt"] = vtm.get(f["sha256"].lower())
    detail.update({
        "tags": [{"tag": t, "label": tags.LABELS.get(t, t)} for t in store.tags_by_ip(con, [ip]).get(ip, [])],
        "session_list": [sessions[k] for k in reversed(order)][:100],
        "credentials": [{"user": u, "password": p, "count": n, "ok": (u, p) in creds_ok}
                        for (u, p), n in creds.most_common(50)],
        "clients": [{"label": k, "count": v} for k, v in clients.most_common()],
        "files": files[-50:][::-1],
    })
    return jsonify(detail)


@app.get("/api/tty/<session>")
def tty_replay(session):
    ready_or_503()
    if not session.isalnum() or len(session) > 64:
        abort(400)
    row = db().execute("SELECT ttylog, ip FROM events WHERE kind='tty' AND session=? ORDER BY id DESC LIMIT 1",
                       (session,)).fetchone()
    path = tty.path_for(row["ttylog"]) if row else None
    if not path:
        abort(404, "Pas d'enregistrement pour cette session")
    frames, truncated = tty.frames(path)
    return jsonify({"session": session, "ip": row["ip"], "frames": frames, "truncated": truncated})


@app.post("/api/alerts/test")
def alerts_test():
    check_csrf()
    if not alerts.CHANNELS:
        abort(400, "Aucune alerte configurée (voir .env)")
    alerts.test_message()
    return jsonify({"ok": True, "channels": alerts.CHANNELS})


@app.get("/api/status")
def status_api():
    return jsonify(status.view())


@app.get("/api/home")
def home_api():
    """Résumé léger pour la page d'accueil : chiffres du honeypot + état des services."""
    hp = None
    if INGESTER.ready.is_set():
        con = db()
        one = lambda sql, a=(): con.execute(sql, a).fetchone()[0]  # noqa: E731
        hp = {"connexions": one("SELECT COUNT(*) FROM events WHERE kind='connect'"),
              "connexions_24h": one("SELECT COUNT(*) FROM events WHERE kind='connect' AND ts >= ?", (store.since_iso(24),)),
              "ips_24h": one("SELECT COUNT(DISTINCT ip) FROM events WHERE kind='connect' AND ts >= ?", (store.since_iso(24),)),
              "ips": one("SELECT COUNT(DISTINCT ip) FROM events WHERE kind='connect'"),
              "first": one("SELECT MIN(ts) FROM events") or "",
              "last": one("SELECT MAX(ts) FROM events") or ""}
    return jsonify({"honeypot": hp, "status": status.summary()})


# ---------- Pages ----------
# /          : accueil (choix entre les espaces, façon Pterodactyl)
# /honeypot  : tableau de bord du honeypot
# /status    : état des sites surveillés
# /soc       : vue SOC du honeypot
@app.get("/")
def home():
    return send_from_directory(STATIC, "home.html", max_age=0)


@app.get("/honeypot")
def honeypot_page():
    return send_from_directory(STATIC, "index.html", max_age=0)


@app.get("/status")
def status_page():
    return send_from_directory(STATIC, "status.html", max_age=0)


@app.get("/soc")
def soc_page():
    return send_from_directory(STATIC, "soc.html", max_age=0)


@app.get("/static/<any('app.js','app.css','portal.js','soc.js'):name>")
def static_file(name):
    return send_from_directory(STATIC, name, max_age=0)


@app.get("/flags/<cc>.svg")
def flag(cc):
    if not geoip.CC_RE.fullmatch(cc):
        abort(404)
    return send_from_directory(os.path.join(geoip.ASSETS, "flags"), f"{cc}.svg", max_age=86400 * 30)


@app.get("/map/land.json")
def land():
    return send_from_directory(geoip.ASSETS, "land-110m.json", max_age=86400 * 30)


# ---------- Tâches de fond ----------
def on_live_event(ev):
    alerts.on_event(ev)
    autoban.on_event(ev)


INGESTER = store.Ingester(on_event=on_live_event)


def _seed_alerts():
    """Les pays déjà vus ne déclenchent pas d'alerte « nouveau pays »."""
    INGESTER.ready.wait()
    con = store.connect(readonly=True)
    alerts.seed_countries(geo(r[0])["cc"] for r in con.execute("SELECT DISTINCT ip FROM events WHERE ip IS NOT NULL"))
    con.close()


def start_background():
    autoban.setup(auto_ban, _notify_ban)
    INGESTER.start()
    alerts.start()
    threading.Thread(target=_expire_bans, daemon=True, name="autoban").start()
    threading.Thread(target=_seed_alerts, daemon=True, name="seed").start()
    vt.start(INGESTER.ready)
    status.start()


start_background()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
