"""Panel web pour le honeypot Cowrie.

Lit les logs JSON de Cowrie et affiche les attaques en direct.
Toutes les données affichées viennent des attaquants : elles sont insérées
dans la page avec textContent (jamais innerHTML) pour éviter toute XSS.
"""
import glob
import ipaddress
import json
import os
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from flask import Flask, Response, abort, jsonify, send_from_directory

try:
    import maxminddb
except ImportError:  # le panel marche aussi sans géolocalisation
    maxminddb = None

DATA = os.environ.get("COWRIE_DATA", "/data")
LOG_GLOB = os.path.join(DATA, "log", "cowrie", "cowrie.json*")
DOWNLOADS = os.path.join(DATA, "lib", "cowrie", "downloads")
# Données téléchargées au build par fetch_assets.py (géoloc DB-IP, carte, drapeaux).
ASSETS = os.environ.get("PANEL_ASSETS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets"))
MAX_IPS = 1500  # IP les plus récentes envoyées au navigateur (tableau + carte)

LOGIN_IDS = ("cowrie.login.failed", "cowrie.login.success")
FILE_IDS = ("cowrie.session.file_download", "cowrie.session.file_upload")
CC_RE = re.compile(r"[a-z]{2}")

app = Flask(__name__)


# ---------- Géolocalisation hors ligne (aucune IP n'est envoyée à un service externe) ----------
def _open_db(name):
    path = os.path.join(ASSETS, name)
    if maxminddb is None or not os.path.exists(path):
        return None
    try:
        return maxminddb.open_database(path)
    except Exception:  # noqa: BLE001
        return None


CITY_DB = _open_db("dbip-city-lite.mmdb")
ASN_DB = _open_db("dbip-asn-lite.mmdb")


def _name(node, lang="fr"):
    names = (node or {}).get("names") or {}
    return names.get(lang) or names.get("en") or ""


@lru_cache(maxsize=65536)
def _geo(ip):
    info = {"cc": "", "country": "", "city": "", "region": "", "continent": "",
            "lat": None, "lon": None, "asn": None, "org": "", "private": False}
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return info
    if not addr.is_global:
        info["private"] = True
        return info
    if CITY_DB:
        try:
            r = CITY_DB.get(ip) or {}
        except Exception:  # noqa: BLE001
            r = {}
        cc = str((r.get("country") or {}).get("iso_code") or "").lower()
        info["cc"] = cc if CC_RE.fullmatch(cc) else ""
        info["country"] = _name(r.get("country"))
        info["city"] = _name(r.get("city"), "en")
        subs = r.get("subdivisions") or []
        info["region"] = _name(subs[0], "en") if subs else ""
        info["continent"] = _name(r.get("continent"))
        loc = r.get("location") or {}
        info["lat"], info["lon"] = loc.get("latitude"), loc.get("longitude")
    if ASN_DB:
        try:
            a = ASN_DB.get(ip) or {}
        except Exception:  # noqa: BLE001
            a = {}
        info["asn"] = a.get("autonomous_system_number")
        info["org"] = a.get("autonomous_system_organization") or ""
    return info


def geo(ip):
    return dict(_geo(ip))  # copie : le cache ne doit pas être modifié


def read_events():
    events = []
    for path in sorted(glob.glob(LOG_GLOB)):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
    events.sort(key=lambda e: e.get("timestamp", ""))
    return events


def summarize_ips(events):
    """Une fiche par IP : première/dernière activité, compteurs et géolocalisation."""
    ips = {}
    for e in events:
        ip = e.get("src_ip")
        if not ip:
            continue
        ts = e.get("timestamp", "")
        s = ips.get(ip)
        if s is None:
            s = ips[ip] = {"ip": ip, "first": ts, "last": ts, "connexions": 0, "sessions": set(),
                           "tentatives": 0, "reussies": 0, "commandes": 0, "fichiers": 0}
        if ts:
            s["last"] = ts  # les événements sont triés par date
        if e.get("session"):
            s["sessions"].add(e["session"])
        eid = e.get("eventid")
        if eid == "cowrie.session.connect":
            s["connexions"] += 1
        elif eid in LOGIN_IDS:
            s["tentatives"] += 1
            s["reussies"] += eid == "cowrie.login.success"
        elif eid == "cowrie.command.input":
            s["commandes"] += 1
        elif eid in FILE_IDS:
            s["fichiers"] += 1
    for s in ips.values():
        s["sessions"] = len(s["sessions"])
        s.update(geo(s["ip"]))
    return ips


@app.get("/api/stats")
def stats():
    events = read_events()
    logins = [e for e in events if e.get("eventid") in LOGIN_IDS]
    success = [e for e in logins if e["eventid"] == "cowrie.login.success"]
    commands = [e for e in events if e.get("eventid") == "cowrie.command.input"]
    connects = [e for e in events if e.get("eventid") == "cowrie.session.connect"]
    clients = [e for e in events if e.get("eventid") == "cowrie.client.version"]
    files = [e for e in events if e.get("eventid") in FILE_IDS]

    per_ip = summarize_ips(events)
    cc_of = lambda ip: per_ip[ip]["cc"] if ip in per_ip else ""  # noqa: E731
    countries = {}
    for s in per_ip.values():
        if not s["cc"]:
            continue
        c = countries.setdefault(s["cc"], {"cc": s["cc"], "country": s["country"], "ips": 0, "connexions": 0})
        c["ips"] += 1
        c["connexions"] += s["connexions"]
    top_countries = sorted(countries.values(), key=lambda c: (-c["ips"], -c["connexions"]))[:10]
    recent_ips = sorted(per_ip.values(), key=lambda s: s["last"], reverse=True)[:MAX_IPS]

    ips = Counter(e.get("src_ip") for e in connects if e.get("src_ip"))
    users = Counter(e.get("username", "") for e in logins)
    passwords = Counter(e.get("password", "") for e in logins)
    combos = Counter(f'{e.get("username", "")} / {e.get("password", "")}' for e in logins)
    top_cmds = Counter(e.get("input", "") for e in commands)
    versions = Counter(str(e.get("version", "")) for e in clients)

    # Activité des 24 dernières heures, heure par heure (y compris les heures vides).
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    buckets = [now - timedelta(hours=i) for i in range(23, -1, -1)]
    conn_h = Counter(e.get("timestamp", "")[:13] for e in connects)
    login_h = Counter(e.get("timestamp", "")[:13] for e in logins)
    per_hour = []
    for b in buckets:
        key = b.strftime("%Y-%m-%dT%H")
        per_hour.append({"ts": b.isoformat(), "connexions": conn_h[key], "tentatives": login_h[key]})

    def top(counter, n=8, with_cc=False):
        rows = [{"label": k, "count": v} for k, v in counter.most_common(n)]
        if with_cc:
            for r in rows:
                r["cc"] = cc_of(r["label"])
        return rows

    try:
        n_downloads = len(os.listdir(DOWNLOADS))
    except OSError:
        n_downloads = 0

    return jsonify({
        "totals": {
            "connexions": len(connects),
            "ips_uniques": len(ips),
            "tentatives": len(logins),
            "reussies": len(success),
            "commandes": len(commands),
            "fichiers": n_downloads,
            "pays": len(countries),
        },
        "geo": CITY_DB is not None,
        "top_ips": top(ips, with_cc=True),
        "top_countries": top_countries,
        "ips": recent_ips,
        "ips_total": len(per_ip),
        "top_users": top(users),
        "top_passwords": top(passwords),
        "top_combos": top(combos),
        "top_commands": top(top_cmds),
        "top_clients": top(versions),
        "per_hour": per_hour,
        "commands": [
            {"ts": e.get("timestamp", ""), "ip": e.get("src_ip", ""), "cc": cc_of(e.get("src_ip")),
             "session": e.get("session", ""), "input": e.get("input", "")}
            for e in commands[-100:]
        ][::-1],
        "logins": [
            {"ts": e.get("timestamp", ""), "ip": e.get("src_ip", ""), "cc": cc_of(e.get("src_ip")),
             "user": e.get("username", ""), "password": e.get("password", ""),
             "ok": e["eventid"] == "cowrie.login.success"}
            for e in logins[-100:]
        ][::-1],
        "files": [
            {"ts": e.get("timestamp", ""), "ip": e.get("src_ip", ""), "cc": cc_of(e.get("src_ip")),
             "url": e.get("url") or e.get("filename", ""), "sha256": e.get("shasum", "")}
            for e in files[-50:]
        ][::-1],
    })


@app.get("/api/ip/<path:ip>")
def ip_detail(ip):
    """Fiche complète d'une IP : géoloc, sessions, identifiants essayés, commandes, fichiers."""
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        abort(400)
    events = [e for e in read_events() if e.get("src_ip") == ip]
    if not events:
        abort(404)
    sessions, order = {}, []
    creds, creds_ok, clients, files = Counter(), set(), Counter(), []
    for e in events:
        sid, ts, eid = e.get("session", ""), e.get("timestamp", ""), e.get("eventid")
        s = sessions.get(sid)
        if s is None:
            s = sessions[sid] = {"id": sid, "start": ts, "end": ts, "protocol": "", "port": None,
                                 "client": "", "duration": None, "logins": [], "commands": [], "files": []}
            order.append(sid)
        if ts:
            s["end"] = ts
        if eid == "cowrie.session.connect":
            s["protocol"] = str(e.get("protocol", ""))
            s["port"] = e.get("dst_port")
        elif eid == "cowrie.client.version":
            s["client"] = str(e.get("version", ""))
            clients[s["client"]] += 1
        elif eid in LOGIN_IDS:
            ok = eid == "cowrie.login.success"
            u, p = str(e.get("username", "")), str(e.get("password", ""))
            s["logins"].append({"ts": ts, "user": u, "password": p, "ok": ok})
            creds[(u, p)] += 1
            if ok:
                creds_ok.add((u, p))
        elif eid == "cowrie.command.input":
            s["commands"].append({"ts": ts, "input": str(e.get("input", ""))})
        elif eid in FILE_IDS:
            f = {"ts": ts, "url": str(e.get("url") or e.get("filename", "")), "sha256": str(e.get("shasum", ""))}
            s["files"].append(f)
            files.append(f)
        elif eid == "cowrie.session.closed":
            try:
                s["duration"] = float(e.get("duration"))
            except (TypeError, ValueError):
                pass
    detail = summarize_ips(events)[ip]
    detail.update({
        "session_list": [sessions[k] for k in reversed(order)][:100],
        "credentials": [{"user": u, "password": p, "count": n, "ok": (u, p) in creds_ok}
                        for (u, p), n in creds.most_common(50)],
        "clients": [{"label": k, "count": v} for k, v in clients.most_common()],
        "files": files[-50:][::-1],
    })
    return jsonify(detail)


@app.get("/flags/<cc>.svg")
def flag(cc):
    if not CC_RE.fullmatch(cc):
        abort(404)
    return send_from_directory(os.path.join(ASSETS, "flags"), f"{cc}.svg", max_age=86400 * 30)


@app.get("/map/land.json")
def land():
    return send_from_directory(ASSETS, "land-110m.json", max_age=86400 * 30)


PAGE = r"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>Honeypot · Cowrie</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🍯</text></svg>">
<style>
:root{
 --bg:#07080c;--bg2:#0d0f16;--card:rgba(255,255,255,.035);--card-h:rgba(255,255,255,.055);
 --line:rgba(255,255,255,.08);--line2:rgba(255,255,255,.14);
 --txt:#eef0f6;--mut:#8a90a2;--dim:#5b6072;
 --acc:#f5a524;--acc2:#ff6a3d;--vio:#8b7bff;--ok:#2fd27a;--ko:#ff5a6a;--info:#4cb2ff;
 --glow1:rgba(245,165,36,.13);--glow2:rgba(139,123,255,.11);
 --shadow:0 1px 0 rgba(255,255,255,.04) inset,0 10px 30px -12px rgba(0,0,0,.6);
 --mono:ui-monospace,"JetBrains Mono","Cascadia Code",Consolas,monospace;
 --r:16px;
}
[data-theme=light]{
 --bg:#f4f5f9;--bg2:#eceef4;--card:rgba(255,255,255,.75);--card-h:#fff;
 --line:rgba(15,20,40,.08);--line2:rgba(15,20,40,.15);
 --txt:#141726;--mut:#5d6378;--dim:#9aa0b2;
 --glow1:rgba(245,165,36,.18);--glow2:rgba(139,123,255,.14);
 --shadow:0 1px 2px rgba(15,20,40,.04),0 8px 24px -12px rgba(15,20,40,.18);
}
*{box-sizing:border-box}
html,body{margin:0}
body{font:14px/1.5 Inter,"Segoe UI Variable","Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--txt);min-height:100vh;
 background-image:radial-gradient(60rem 30rem at 10% -10%,var(--glow1),transparent 60%),radial-gradient(50rem 30rem at 100% 0%,var(--glow2),transparent 60%);background-attachment:fixed;-webkit-font-smoothing:antialiased}
::selection{background:rgba(245,165,36,.35)}
button,input{font:inherit;color:inherit}

/* ---------- En-tête ---------- */
.top{position:sticky;top:0;z-index:20;display:flex;justify-content:space-between;align-items:center;gap:16px;padding:14px 28px;
 background:color-mix(in srgb,var(--bg) 72%,transparent);backdrop-filter:blur(14px) saturate(140%);-webkit-backdrop-filter:blur(14px) saturate(140%);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;font-size:20px;
 background:linear-gradient(135deg,var(--acc),var(--acc2));box-shadow:0 6px 20px -6px rgba(255,106,61,.6)}
.brand h1{margin:0;font-size:16px;font-weight:650;letter-spacing:-.01em}
.brand p{margin:0;font-size:12px;color:var(--mut)}
.actions{display:flex;align-items:center;gap:8px}
.status{display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border-radius:999px;font-size:12px;color:var(--mut);border:1px solid var(--line);background:var(--card)}
.status i{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 0 rgba(47,210,122,.6);animation:pulse 2s infinite}
.status.paused i{background:var(--acc);animation:none}
.status.err i{background:var(--ko);animation:none}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(47,210,122,.55)}70%{box-shadow:0 0 0 8px rgba(47,210,122,0)}100%{box-shadow:0 0 0 0 rgba(47,210,122,0)}}
.btn{display:inline-flex;align-items:center;gap:6px;height:32px;padding:0 12px;border-radius:10px;border:1px solid var(--line);background:var(--card);cursor:pointer;font-size:12.5px;transition:.15s}
.btn:hover{background:var(--card-h);border-color:var(--line2)}
.btn svg{width:15px;height:15px}
.btn.icon{width:32px;padding:0;justify-content:center}

/* ---------- Mise en page ---------- */
main{max-width:1480px;margin:0 auto;padding:24px 28px 48px;display:grid;gap:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:18px 20px;box-shadow:var(--shadow);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);min-width:0}
.card-h{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.card h2{margin:0;font-size:13px;font-weight:600;letter-spacing:.01em}
.card h2 small{display:block;font-weight:400;color:var(--mut);font-size:12px;margin-top:2px}
.muted{color:var(--mut);font-size:12px}
.row{display:grid;grid-template-columns:minmax(0,2.2fr) minmax(280px,1fr);gap:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:20px}
@media (max-width:900px){.row{grid-template-columns:1fr}.top{padding:12px 16px}main{padding:16px}.brand p{display:none}}

/* ---------- KPI ---------- */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px}
.kpi{position:relative;overflow:hidden;padding:16px 18px;transition:transform .2s,border-color .2s}
.kpi:hover{transform:translateY(-2px);border-color:var(--line2)}
.kpi::after{content:"";position:absolute;right:-30px;top:-30px;width:110px;height:110px;border-radius:50%;background:var(--c);opacity:.09;filter:blur(8px)}
.kpi-top{display:flex;align-items:center;justify-content:space-between}
.kpi .ic{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;color:var(--c);background:color-mix(in srgb,var(--c) 14%,transparent)}
.kpi .ic svg{width:18px;height:18px}
.kpi .val{font-size:30px;font-weight:700;letter-spacing:-.03em;margin-top:14px;font-variant-numeric:tabular-nums;line-height:1.1}
.kpi .lbl{color:var(--mut);font-size:12.5px;margin-top:2px}
.delta{font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;color:var(--ok);background:rgba(47,210,122,.12);opacity:0;transform:translateY(-4px);transition:.3s}
.delta.show{opacity:1;transform:none}

/* ---------- Graphique ---------- */
.legend{display:flex;gap:14px;font-size:12px;color:var(--mut)}
.legend span{display:inline-flex;align-items:center;gap:6px}
.legend i{width:10px;height:10px;border-radius:3px;background:var(--c)}
.chart{position:relative;height:240px}
.chart svg{display:block;overflow:visible}
.chart .gl{stroke:var(--line);stroke-dasharray:3 4}
.chart .ax{fill:var(--dim);font-size:10.5px;font-family:var(--mono)}
.chart .cursor{stroke:var(--line2);opacity:0;transition:opacity .15s}
.chart .dot{opacity:0;transition:opacity .15s}
.chart:hover .cursor,.chart:hover .dot{opacity:1}
.tip{position:absolute;pointer-events:none;background:var(--bg2);border:1px solid var(--line2);border-radius:10px;padding:8px 10px;font-size:12px;box-shadow:0 10px 30px -10px rgba(0,0,0,.5);opacity:0;transition:opacity .15s;white-space:nowrap;transform:translate(-50%,-110%)}
.chart:hover .tip{opacity:1}
.tip b{display:block;margin-bottom:4px;font-weight:600}
.tip div{display:flex;align-items:center;gap:6px;color:var(--mut)}
.tip div i{width:8px;height:8px;border-radius:2px;background:var(--c)}
.tip div em{font-style:normal;color:var(--txt);margin-left:auto;padding-left:12px;font-variant-numeric:tabular-nums}

/* ---------- Donut ---------- */
.donut{display:flex;flex-direction:column;align-items:center;gap:16px;padding-top:6px}
.donut .ring{position:relative;width:170px;height:170px}
.donut .ring svg{transform:rotate(-90deg)}
.donut circle{fill:none;stroke-width:14;stroke-linecap:round;transition:stroke-dasharray .8s cubic-bezier(.2,.8,.2,1)}
.donut .center{position:absolute;inset:0;display:grid;place-content:center;text-align:center}
.donut .center b{font-size:28px;font-weight:700;letter-spacing:-.03em}
.donut .center small{color:var(--mut);font-size:11.5px}
.donut .split{display:grid;grid-template-columns:1fr 1fr;gap:10px;width:100%}
.donut .split div{border:1px solid var(--line);border-radius:12px;padding:10px 12px}
.donut .split small{display:flex;align-items:center;gap:6px;color:var(--mut);font-size:11.5px}
.donut .split small i{width:8px;height:8px;border-radius:50%;background:var(--c)}
.donut .split b{font-size:18px;font-variant-numeric:tabular-nums}

/* ---------- Classements ---------- */
.rank{display:grid;gap:6px}
.rk{display:grid;grid-template-columns:22px minmax(0,1fr) auto;gap:10px;align-items:center;padding:6px 8px;border-radius:10px;transition:background .15s}
.rk:hover{background:var(--card-h)}
.rk .n{font-size:11px;color:var(--dim);font-variant-numeric:tabular-nums;text-align:center}
.rk:nth-child(1) .n{color:var(--acc);font-weight:700}
.rk .lb{min-width:0}
.rk .lb span{display:block;font-family:var(--mono);font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rk .tr{height:4px;margin-top:5px;border-radius:99px;background:var(--line);overflow:hidden}
.rk .tr i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--acc),var(--acc2));transition:width .6s cubic-bezier(.2,.8,.2,1)}
.rk .ct{font-size:12px;color:var(--mut);font-variant-numeric:tabular-nums;min-width:34px;text-align:right}
.rk.ip{cursor:pointer}

/* ---------- Flux ---------- */
.tabs{display:inline-flex;gap:4px;padding:4px;border-radius:12px;background:var(--bg2);border:1px solid var(--line)}
.tab{border:0;background:transparent;padding:6px 12px;border-radius:9px;cursor:pointer;font-size:12.5px;color:var(--mut);display:inline-flex;align-items:center;gap:8px;transition:.15s}
.tab:hover{color:var(--txt)}
.tab.on{background:var(--card-h);color:var(--txt);box-shadow:0 1px 3px rgba(0,0,0,.25)}
.tab em{font-style:normal;font-size:11px;padding:0 7px;border-radius:99px;background:var(--line);font-variant-numeric:tabular-nums}
.search{position:relative}
.search svg{position:absolute;left:10px;top:50%;width:14px;height:14px;transform:translateY(-50%);color:var(--dim)}
.search input{height:34px;width:240px;max-width:60vw;padding:0 12px 0 32px;border-radius:10px;border:1px solid var(--line);background:var(--bg2);outline:none;transition:.15s}
.search input:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(245,165,36,.18)}
.tw{overflow:auto;max-height:520px;border-radius:12px;border:1px solid var(--line)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{position:sticky;top:0;z-index:1;background:var(--bg2);color:var(--mut);font-weight:500;font-size:11.5px;text-transform:uppercase;letter-spacing:.05em}
td,th{padding:10px 14px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
tr:last-child td{border-bottom:0}
tbody tr{transition:background .15s}
tbody tr:hover{background:var(--card-h)}
td.t{color:var(--mut);white-space:nowrap;font-variant-numeric:tabular-nums}
td.ip{font-family:var(--mono);white-space:nowrap;cursor:pointer;color:var(--info)}
td.ip:hover{text-decoration:underline}
td.code{font-family:var(--mono);word-break:break-all}
td.code.cmd::before{content:"$ ";color:var(--acc)}
td.sess{font-family:var(--mono);color:var(--dim);white-space:nowrap}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;font-weight:600;padding:2px 10px;border-radius:99px}
.pill::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.pill.ok{color:var(--ok);background:rgba(47,210,122,.12)}
.pill.ko{color:var(--ko);background:rgba(255,90,106,.12)}
tr.new{animation:flash 2.4s ease-out}
@keyframes flash{0%{background:rgba(245,165,36,.22)}100%{background:transparent}}
.empty{display:grid;place-items:center;gap:6px;padding:28px 10px;color:var(--dim);font-size:12.5px;text-align:center}
.empty svg{width:26px;height:26px;opacity:.6}

/* ---------- Toast ---------- */
#toast{position:fixed;left:50%;bottom:24px;transform:translate(-50%,20px);opacity:0;pointer-events:none;padding:10px 16px;border-radius:12px;background:var(--bg2);border:1px solid var(--line2);font-size:13px;box-shadow:0 10px 30px -10px rgba(0,0,0,.5);transition:.25s;z-index:50}
#toast.show{opacity:1;transform:translate(-50%,0)}
.skel{height:14px;border-radius:6px;background:linear-gradient(90deg,var(--line) 25%,var(--line2) 50%,var(--line) 75%);background-size:200% 100%;animation:sk 1.2s infinite}
@keyframes sk{to{background-position:-200% 0}}
/* ---------- Drapeaux ---------- */
.flag{display:inline-block;width:20px;height:15px;border-radius:3px;object-fit:cover;vertical-align:-2px;flex:none;box-shadow:0 0 0 1px var(--line2)}
.flag.none{background:var(--line);box-shadow:none}
.flag.lg{width:44px;height:33px;border-radius:6px}
.iptag{display:inline-flex;align-items:center;gap:8px}
.rk .lb span .flag{margin-right:8px}

/* ---------- Carte ---------- */
.map{position:relative;border-radius:12px;overflow:hidden;background:var(--bg2);border:1px solid var(--line)}
.map svg{display:block;width:100%;height:auto}
.map .land{fill:color-mix(in srgb,var(--txt) 9%,transparent);stroke:color-mix(in srgb,var(--txt) 16%,transparent);stroke-width:.6;fill-rule:evenodd}
.map .grat{stroke:var(--line);stroke-width:.6;stroke-dasharray:2 4}
.map .pt{cursor:pointer}
.map .pt circle.c{fill:var(--acc);fill-opacity:.55;stroke:var(--acc);stroke-width:1.2;transition:fill-opacity .15s}
.map .pt.ok circle.c{fill:var(--ko);stroke:var(--ko)}
.map .pt:hover circle.c{fill-opacity:.9}
.map .pt circle.p{fill:none;stroke:var(--acc);stroke-width:1.5;transform-box:fill-box;transform-origin:center;animation:ping 2s ease-out infinite}
.map .pt.ok circle.p{stroke:var(--ko)}
@keyframes ping{0%{transform:scale(1);opacity:.9}100%{transform:scale(3.2);opacity:0}}
.maptip{transform:translate(-50%,calc(-100% - 12px))}
.maptip.on{opacity:1}
.maptip.below{transform:translate(-50%,16px)}
.maptip b{display:flex;align-items:center;gap:8px}
.maptip .ips{margin-top:4px;font-family:var(--mono);font-size:11.5px;color:var(--mut);display:block}
.map-empty{position:absolute;inset:0;display:grid;place-items:center;color:var(--dim);font-size:12.5px;pointer-events:none}

/* ---------- Tableau des IP ---------- */
th.sort{cursor:pointer;user-select:none;white-space:nowrap}
th.sort:hover{color:var(--txt)}
th.sort.on{color:var(--acc)}
th.sort.on::after{content:" ↓"}
th.sort.on.asc::after{content:" ↑"}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
#iptable tbody tr{cursor:pointer}
td.loc{white-space:nowrap}
td.loc small{display:block;color:var(--mut);font-size:11.5px;margin-left:28px}
td.org{color:var(--mut);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
td.mono{font-family:var(--mono)}
.zero{color:var(--dim)}

/* ---------- Panneau de détail d'une IP ---------- */
#scrim{position:fixed;inset:0;background:rgba(0,0,0,.45);opacity:0;pointer-events:none;transition:opacity .2s;z-index:40}
#scrim.open{opacity:1;pointer-events:auto}
#drawer{position:fixed;top:0;right:0;bottom:0;width:min(600px,100vw);background:var(--bg2);border-left:1px solid var(--line2);z-index:45;
 transform:translateX(100%);transition:transform .25s cubic-bezier(.2,.8,.2,1);overflow-y:auto;box-shadow:-20px 0 60px -20px rgba(0,0,0,.6)}
#drawer.open{transform:none}
.dw{padding:22px 24px 40px;display:grid;gap:20px}
.dw-h{display:flex;gap:14px;align-items:center}
.dw-h h3{margin:0;font-family:var(--mono);font-size:20px;letter-spacing:-.01em;word-break:break-all}
.dw-h p{margin:2px 0 0;color:var(--mut);font-size:12.5px}
.dw-h .btn{margin-left:auto;flex:none}
.dw-act{display:flex;gap:8px;flex-wrap:wrap}
.dw h4{margin:0 0 10px;font-size:12px;font-weight:600;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}
.mini{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.mini div{border:1px solid var(--line);border-radius:12px;padding:10px 12px;background:var(--card)}
.mini b{display:block;font-size:20px;font-variant-numeric:tabular-nums;letter-spacing:-.02em}
.mini small{color:var(--mut);font-size:11.5px}
.info{display:grid;grid-template-columns:130px minmax(0,1fr);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.info dt,.info dd{margin:0;padding:8px 12px;border-bottom:1px solid var(--line);font-size:12.5px}
.info dt{color:var(--mut);background:var(--card)}
.info dd{word-break:break-word;display:flex;align-items:center;gap:8px}
.info dt:nth-last-child(2),.info dd:last-child{border-bottom:0}
.links{display:flex;gap:8px;flex-wrap:wrap}
.links a{text-decoration:none}
.sess{border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-bottom:10px}
.sess-h{display:flex;flex-wrap:wrap;gap:6px 14px;padding:9px 12px;background:var(--card);font-size:12px;color:var(--mut)}
.sess-h b{color:var(--txt);font-weight:600}
.sess-b{padding:8px 12px;display:grid;gap:4px;font-family:var(--mono);font-size:12px}
.sess-b .c::before{content:"$ ";color:var(--acc)}
.sess-b .c{word-break:break-all}
.sess-b .l{color:var(--mut)}
.sess-b .l.ok{color:var(--ok)}
.foot{max-width:1480px;margin:0 auto;padding:0 28px 32px;color:var(--dim);font-size:11.5px}
.foot a{color:var(--mut)}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style></head><body>

<header class="top">
 <div class="brand">
  <div class="logo">🍯</div>
  <div><h1>Honeypot Cowrie</h1><p>Faux SSH :2222 · Faux Telnet :2223</p></div>
 </div>
 <div class="actions">
  <span class="status" id="status"><i></i><span id="live">connexion…</span></span>
  <button class="btn" id="pause" title="Mettre en pause l'actualisation"></button>
  <button class="btn icon" id="theme" title="Changer de thème"></button>
 </div>
</header>

<main>
 <section class="kpis" id="kpis"></section>

 <section class="row">
  <div class="card">
   <div class="card-h">
    <h2>Activité des 24 dernières heures<small id="hours-total">&nbsp;</small></h2>
    <div class="legend"><span style="--c:var(--acc)"><i></i>Connexions</span><span style="--c:var(--vio)"><i></i>Tentatives de login</span></div>
   </div>
   <div class="chart" id="chart"></div>
  </div>
  <div class="card">
   <div class="card-h"><h2>Logins réussis<small>part des tentatives acceptées</small></h2></div>
   <div class="donut" id="donut"></div>
  </div>
 </section>

 <section class="row">
  <div class="card">
   <div class="card-h">
    <h2>Carte des connexions<small id="map-sub">&nbsp;</small></h2>
    <div class="legend"><span style="--c:var(--acc)"><i></i>Attaquant</span><span style="--c:var(--ko)"><i></i>Login réussi</span></div>
   </div>
   <div class="map" id="map"></div>
  </div>
  <div class="card">
   <div class="card-h"><h2>Pays d'origine<small>nombre d'IP par pays</small></h2></div>
   <div class="rank" id="countries"></div>
  </div>
 </section>

 <section class="grid" id="ranks"></section>

 <section class="card">
  <div class="card-h">
   <h2>Adresses IP<small id="ip-sub">cliquer sur une IP pour voir sa fiche</small></h2>
   <label class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
    <input type="search" id="ipfilter" placeholder="Filtrer (IP, pays, ville, AS…)" autocomplete="off"></label>
  </div>
  <div class="tw"><table id="iptable"></table></div>
 </section>

 <section class="card">
  <div class="card-h">
   <div class="tabs" id="tabs"></div>
   <label class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
    <input type="search" id="filter" placeholder="Filtrer (IP, commande, mot de passe…)" autocomplete="off"></label>
  </div>
  <div class="tw"><table id="feed"></table></div>
 </section>
</main>
<footer class="foot"><a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">IP Geolocation by DB-IP</a> (CC BY 4.0) · Carte : Natural Earth · Drapeaux : flag-icons · Géolocalisation hors ligne : aucune IP n'est envoyée à un service externe.</footer>
<div id="scrim"></div>
<aside id="drawer" aria-hidden="true" aria-label="Fiche IP"></aside>
<div id="toast"></div>

<script>
"use strict";
/* Rappel : tout ce qui vient des logs est inséré avec textContent uniquement. */
const $=s=>document.querySelector(s);
const NS="http://www.w3.org/2000/svg";
const REFRESH_MS=5000;

const ICONS={ /* icônes fixes (pas de données attaquant) */
 activity:'<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
 globe:'<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/>',
 key:'<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
 unlock:'<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
 terminal:'<path d="m4 17 6-6-6-6M12 19h8"/>',
 file:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
 pause:'<rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/>',
 play:'<path d="M6 4l14 8-14 8z"/>',
 sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
 moon:'<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
 inbox:'<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.5 5.1 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.5-6.9A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.7 1.1z"/>',
 flag:'<path d="M4 22V4a1 1 0 0 1 .4-.8A6 6 0 0 1 8 2c3 0 5 2 8 2a6 6 0 0 0 4-1.5V14a6 6 0 0 1-4 1.5c-3 0-5-2-8-2a6 6 0 0 0-4 1.5"/>',
 x:'<path d="M18 6 6 18M6 6l12 12"/>',
 copy:'<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
 filter:'<path d="M22 3H2l8 9.5V19l4 2v-8.5z"/>',
 ext:'<path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
};
function icon(name){const s=document.createElementNS(NS,"svg");s.setAttribute("viewBox","0 0 24 24");s.setAttribute("fill","none");s.setAttribute("stroke","currentColor");
 s.setAttribute("stroke-width","2");s.setAttribute("stroke-linecap","round");s.setAttribute("stroke-linejoin","round");s.innerHTML=ICONS[name];return s}
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined&&text!==null)e.textContent=String(text);return e}
function svg(tag,attrs){const e=document.createElementNS(NS,tag);for(const k in attrs)e.setAttribute(k,attrs[k]);return e}
function emptyBox(msg){const d=el("div","empty");d.append(icon("inbox"),el("span","",msg||"Rien pour l'instant"));return d}
const nf=new Intl.NumberFormat("fr-FR");
const fmtTime=ts=>{const d=new Date(ts);return isNaN(d)?(ts||""):d.toLocaleString("fr-FR",{day:"2-digit",month:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"})};
const fmtHour=ts=>{const d=new Date(ts);return isNaN(d)?"":String(d.getHours()).padStart(2,"0")+"h"};
let toastT;function toast(msg){const t=$("#toast");t.textContent=msg;t.classList.add("show");clearTimeout(toastT);toastT=setTimeout(()=>t.classList.remove("show"),1800)}
function copy(text){if(!text)return;(navigator.clipboard?navigator.clipboard.writeText(text):Promise.reject()).then(()=>toast("Copié : "+text),()=>toast(text))}

/* ---------- Drapeaux / pays ---------- */
const CC_RE=/^[a-z]{2}$/;
const regionName=(()=>{try{const dn=new Intl.DisplayNames(["fr"],{type:"region"});return cc=>{try{return dn.of(cc.toUpperCase())}catch(e){return cc.toUpperCase()}}}catch(e){return cc=>cc.toUpperCase()}})();
function flag(cc,cls){if(!cc||!CC_RE.test(cc))return el("span","flag none"+(cls?" "+cls:""));
 const i=el("img","flag"+(cls?" "+cls:""));i.src="/flags/"+cc+".svg";i.alt=cc.toUpperCase();i.title=regionName(cc);i.loading="lazy";i.decoding="async";return i}
const countryOf=r=>r.private?"Réseau local":(r.country||(r.cc?regionName(r.cc):"Inconnu"));
const placeOf=r=>r.private?"Réseau local":[r.city,r.region,countryOf(r)].filter((v,i,a)=>v&&a.indexOf(v)===i).join(", ");
function ipTag(ip,cc){const s=el("span","iptag");s.append(flag(cc),el("span","",ip));return s}
const fmtDur=s=>{if(s==null||isNaN(s))return"";s=Math.round(s);if(s<60)return s+" s";if(s<3600)return Math.floor(s/60)+" min "+(s%60)+" s";return Math.floor(s/3600)+" h "+Math.floor(s%3600/60)+" min"};
const ago=ts=>{const d=Date.now()-new Date(ts);if(isNaN(d))return"";const m=Math.round(d/6e4);if(m<1)return"à l'instant";if(m<60)return"il y a "+m+" min";const h=Math.round(m/60);if(h<48)return"il y a "+h+" h";return"il y a "+Math.round(h/24)+" j"};

/* ---------- Thème ---------- */
function applyTheme(t){document.documentElement.dataset.theme=t;$("#theme").replaceChildren(icon(t==="light"?"moon":"sun"));localStorage.setItem("theme",t)}
applyTheme(localStorage.getItem("theme")||(matchMedia("(prefers-color-scheme: light)").matches?"light":"dark"));
$("#theme").onclick=()=>{applyTheme(document.documentElement.dataset.theme==="light"?"dark":"light");if(last)drawChart(last.per_hour)};

/* ---------- KPI ---------- */
const KPIS=[
 ["connexions","Connexions","activity","var(--acc)"],
 ["ips_uniques","IP uniques","globe","var(--info)"],
 ["pays","Pays d'origine","flag","var(--ok)"],
 ["tentatives","Tentatives de login","key","var(--vio)"],
 ["reussies","Logins réussis","unlock","var(--ko)"],
 ["commandes","Commandes tapées","terminal","var(--acc2)"],
 ["fichiers","Fichiers capturés","file","#e879f9"],
];
const kpiNodes={};
$("#kpis").replaceChildren(...KPIS.map(([k,label,ic,c])=>{
 const card=el("div","card kpi");card.style.setProperty("--c",c);
 const top=el("div","kpi-top"),chip=el("div","ic"),delta=el("span","delta");chip.append(icon(ic));top.append(chip,delta);
 const val=el("div","val");val.append(el("div","skel"));val.firstChild.style.width="60%";val.firstChild.style.height="28px";
 card.append(top,val,el("div","lbl",label));kpiNodes[k]={val,delta,cur:null};return card}));
function countUp(node,from,to){const t0=performance.now(),d=700;
 (function step(t){const p=Math.min(1,(t-t0)/d),e=1-Math.pow(1-p,3);node.textContent=nf.format(Math.round(from+(to-from)*e));if(p<1)requestAnimationFrame(step)})(t0)}
function updateKpis(totals){
 for(const [k] of KPIS){const n=kpiNodes[k],v=totals[k]||0;
  if(n.cur===null){countUp(n.val,0,v)}
  else if(v!==n.cur){countUp(n.val,n.cur,v);if(v>n.cur){n.delta.textContent="+"+nf.format(v-n.cur);n.delta.classList.add("show");clearTimeout(n.dt);n.dt=setTimeout(()=>n.delta.classList.remove("show"),4000)}}
  n.cur=v}}

/* ---------- Graphique 24 h ---------- */
function niceMax(v){if(v<=4)return 4;const p=Math.pow(10,Math.floor(Math.log10(v))),m=v/p;return (m<=1?1:m<=2?2:m<=5?5:10)*p}
function drawChart(rows){
 const box=$("#chart"),W=Math.max(320,box.clientWidth),H=box.clientHeight||240,P={l:34,r:8,t:10,b:24};
 const iw=W-P.l-P.r,ih=H-P.t-P.b,max=niceMax(Math.max(1,...rows.map(r=>Math.max(r.connexions,r.tentatives))));
 const x=i=>P.l+i*iw/Math.max(1,rows.length-1),y=v=>P.t+ih*(1-v/max);
 const s=svg("svg",{viewBox:`0 0 ${W} ${H}`,width:W,height:H});
 const defs=svg("defs",{});
 [["ga","var(--acc)"],["gv","var(--vio)"]].forEach(([id,c])=>{const g=svg("linearGradient",{id,x1:0,y1:0,x2:0,y2:1});
  g.append(svg("stop",{offset:"0%","stop-color":c,"stop-opacity":.35}),svg("stop",{offset:"100%","stop-color":c,"stop-opacity":0}));defs.append(g)});
 s.append(defs);
 for(let i=0;i<=4;i++){const v=max*i/4,yy=y(v);s.append(svg("line",{class:"gl",x1:P.l,x2:W-P.r,y1:yy,y2:yy}));
  const t=svg("text",{class:"ax",x:P.l-8,y:yy+3.5,"text-anchor":"end"});t.textContent=nf.format(v);s.append(t)}
 rows.forEach((r,i)=>{if(i%3===0||i===rows.length-1){const t=svg("text",{class:"ax",x:x(i),y:H-6,"text-anchor":"middle"});t.textContent=fmtHour(r.ts);s.append(t)}});
 const smooth=pts=>pts.map((p,i)=>{if(!i)return`M${p[0]},${p[1]}`;const q=pts[i-1],cx=(q[0]+p[0])/2;return`C${cx},${q[1]} ${cx},${p[1]} ${p[0]},${p[1]}`}).join("");
 [["tentatives","var(--vio)","gv"],["connexions","var(--acc)","ga"]].forEach(([k,c,g])=>{
  const pts=rows.map((r,i)=>[x(i),y(r[k])]),line=smooth(pts);
  s.append(svg("path",{d:`${line}L${x(rows.length-1)},${y(0)}L${x(0)},${y(0)}Z`,fill:`url(#${g})`}));
  s.append(svg("path",{d:line,fill:"none",stroke:c,"stroke-width":2.2,"stroke-linejoin":"round"}))});
 const cur=svg("line",{class:"cursor",y1:P.t,y2:H-P.b,x1:0,x2:0});
 const da=svg("circle",{class:"dot",r:4,fill:"var(--acc)",stroke:"var(--bg)","stroke-width":2}),dv=svg("circle",{class:"dot",r:4,fill:"var(--vio)",stroke:"var(--bg)","stroke-width":2});
 s.append(cur,dv,da);
 const tip=el("div","tip"),tb=el("b"),l1=el("div"),l2=el("div"),e1=el("em"),e2=el("em");
 const i1=el("i");i1.style.setProperty("--c","var(--acc)");const i2=el("i");i2.style.setProperty("--c","var(--vio)");
 l1.append(i1,"Connexions",e1);l2.append(i2,"Tentatives",e2);tip.append(tb,l1,l2);
 function at(i){const r=rows[i],xx=x(i);cur.setAttribute("x1",xx);cur.setAttribute("x2",xx);
  da.setAttribute("cx",xx);da.setAttribute("cy",y(r.connexions));dv.setAttribute("cx",xx);dv.setAttribute("cy",y(r.tentatives));
  const d=new Date(r.ts),f=new Date(d.getTime()+3600e3);tb.textContent=fmtHour(r.ts)+" – "+fmtHour(f.toISOString());
  e1.textContent=nf.format(r.connexions);e2.textContent=nf.format(r.tentatives);
  tip.style.left=Math.min(W-70,Math.max(70,xx))+"px";tip.style.top=Math.min(y(Math.max(r.connexions,r.tentatives)),ih)+"px"}
 s.addEventListener("mousemove",ev=>{const b=s.getBoundingClientRect(),px=(ev.clientX-b.left)*W/b.width;
  at(Math.max(0,Math.min(rows.length-1,Math.round((px-P.l)/iw*(rows.length-1)))))});
 at(rows.length-1);
 box.replaceChildren(s,tip);
 const tot=rows.reduce((a,r)=>a+r.connexions,0);
 $("#hours-total").textContent=nf.format(tot)+" connexion"+(tot>1?"s":"")+" · "+nf.format(rows.reduce((a,r)=>a+r.tentatives,0))+" tentatives";
}
let rT;addEventListener("resize",()=>{clearTimeout(rT);rT=setTimeout(()=>last&&drawChart(last.per_hour),120)});

/* ---------- Donut ---------- */
const R=70,C=2*Math.PI*R;
const dn={};(function(){const box=$("#donut"),ring=el("div","ring"),s=svg("svg",{viewBox:"0 0 170 170",width:170,height:170});
 s.append(svg("circle",{cx:85,cy:85,r:R,stroke:"var(--line)"}));dn.fg=svg("circle",{cx:85,cy:85,r:R,stroke:"var(--ok)","stroke-dasharray":`0 ${C}`});s.append(dn.fg);
 const c=el("div","center");dn.pct=el("b","","—");c.append(dn.pct,el("small","","de réussite"));ring.append(s,c);
 const split=el("div","split");const mk=(lbl,col)=>{const d=el("div"),sm=el("small"),i=el("i");i.style.setProperty("--c",col);sm.append(i,lbl);const b=el("b","","0");d.append(sm,b);split.append(d);return b};
 dn.ok=mk("Acceptés","var(--ok)");dn.ko=mk("Refusés","var(--ko)");box.append(ring,split)})();
function updateDonut(ok,total){const ko=total-ok,p=total?ok/total:0;
 dn.fg.setAttribute("stroke-dasharray",`${total?Math.max(.5,C*p):0} ${C}`);dn.pct.textContent=total?(p*100).toFixed(p<.1?1:0)+" %":"—";
 dn.ok.textContent=nf.format(ok);dn.ko.textContent=nf.format(ko)}

/* ---------- Classements ---------- */
const RANKS=[["top_ips","Top IP attaquantes","cliquer pour voir la fiche",true],["top_combos","Top combinaisons","identifiant / mot de passe"],
 ["top_users","Top identifiants",""],["top_passwords","Top mots de passe",""],["top_commands","Commandes les plus tapées",""],["top_clients","Clients SSH","version annoncée par l'attaquant"]];
const rankBoxes={};
$("#ranks").replaceChildren(...RANKS.map(([k,title,sub])=>{const c=el("div","card"),h=el("div","card-h"),h2=el("h2","",title);
 if(sub)h2.append(el("small","",sub));h.append(h2);const b=el("div","rank");for(let i=0;i<4;i++){const s=el("div","skel");s.style.margin="8px 0";b.append(s)}
 c.append(h,b);rankBoxes[k]=b;return c}));
function updateRank(k,rows,isIp){const box=rankBoxes[k];if(!rows.length)return box.replaceChildren(emptyBox());
 const max=Math.max(...rows.map(r=>r.count));
 box.replaceChildren(...rows.map((r,i)=>{const row=el("div","rk"+(isIp?" ip":"")),lb=el("div","lb"),tr=el("div","tr"),fill=el("i");
  fill.style.width=(r.count/max*100)+"%";tr.append(fill);const label=r.label===""?"(vide)":r.label;
  const sp=el("span");if(isIp)sp.append(flag(r.cc));sp.append(label);lb.append(sp,tr);lb.title=label;
  row.append(el("span","n",i+1),lb,el("span","ct",nf.format(r.count)));if(isIp)row.onclick=()=>openIp(r.label);return row}))}

/* ---------- Pays ---------- */
function updateCountries(rows){const box=$("#countries");if(!rows.length)return box.replaceChildren(emptyBox(last&&!last.geo?"Base de géolocalisation absente":"Rien pour l'instant"));
 const max=Math.max(...rows.map(r=>r.ips));
 box.replaceChildren(...rows.map((r,i)=>{const row=el("div","rk ip"),lb=el("div","lb"),tr=el("div","tr"),fill=el("i");
  fill.style.width=(r.ips/max*100)+"%";tr.append(fill);const sp=el("span");sp.append(flag(r.cc),countryOf(r));lb.append(sp,tr);
  lb.title=nf.format(r.connexions)+" connexion"+(r.connexions>1?"s":"");
  row.append(el("span","n",i+1),lb,el("span","ct",nf.format(r.ips)+" IP"));
  row.onclick=()=>{$("#ipfilter").value=countryOf(r);renderIps();$("#iptable").closest(".card").scrollIntoView({behavior:"smooth",block:"start"})};return row}))}

/* ---------- Carte (projection équirectangulaire, contours Natural Earth en TopoJSON) ---------- */
const MAP={W:1000,top:84,bot:-58};MAP.H=MAP.W*(MAP.top-MAP.bot)/360;
const mx=lon=>(lon+180)/360*MAP.W,my=lat=>(MAP.top-lat)/360*MAP.W;
const map={};
function topoPath(t){const [sx,sy]=t.transform.scale,[tx,ty]=t.transform.translate;
 const arcs=t.arcs.map(a=>{let x=0,y=0;return a.map(([dx,dy])=>{x+=dx;y+=dy;return[mx(x*sx+tx),my(y*sy+ty)]})});
 const ring=r=>{const pts=[];r.forEach(i=>{const a=i<0?arcs[~i].slice().reverse():arcs[i];pts.push(...(pts.length?a.slice(1):a))});
  /* un saut de plus d'une demi-largeur = passage de l'antiméridien : on lève le crayon au lieu de tracer une ligne à travers la carte */
  return pts.map((p,i)=>(i&&Math.abs(p[0]-pts[i-1][0])<MAP.W/2?"L":"M")+p[0].toFixed(1)+","+p[1].toFixed(1)).join("")+"Z"};
 let d="";for(const g of Object.values(t.objects)[0].geometries){const polys=g.type==="Polygon"?[g.arcs]:g.type==="MultiPolygon"?g.arcs:[];for(const p of polys)for(const r of p)d+=ring(r)}
 return d}
(function initMap(){const box=$("#map");map.svg=svg("svg",{viewBox:`0 0 ${MAP.W} ${MAP.H.toFixed(1)}`});
 for(let lon=-150;lon<=150;lon+=30)map.svg.append(svg("line",{class:"grat",x1:mx(lon),x2:mx(lon),y1:0,y2:MAP.H}));
 for(let lat=-30;lat<=60;lat+=30)map.svg.append(svg("line",{class:"grat",x1:0,x2:MAP.W,y1:my(lat),y2:my(lat)}));
 const land=svg("path",{class:"land"});map.dots=svg("g",{});map.svg.append(land,map.dots);
 map.tip=el("div","tip maptip");map.empty=el("div","map-empty");box.replaceChildren(map.svg,map.tip,map.empty);
 fetch("/map/land.json").then(r=>r.ok?r.json():null).then(t=>{if(t)land.setAttribute("d",topoPath(t))}).catch(()=>{});
 box.addEventListener("mouseleave",()=>map.tip.classList.remove("on"))})();
function mapTip(g,ev){const b=$("#map").getBoundingClientRect(),t=map.tip;
 const h=el("b");h.append(flag(g.cc),placeOf(g));
 const l1=el("div"),e1=el("em",""),l2=el("div"),e2=el("em","");
 l1.append("Adresses IP",e1);e1.textContent=nf.format(g.ips.length);l2.append("Connexions",e2);e2.textContent=nf.format(g.conn);
 const list=el("span","ips",g.ips.slice(0,4).map(r=>r.ip).join("  ")+(g.ips.length>4?"  +"+(g.ips.length-4):""));
 t.replaceChildren(h,l1,l2,list);t.style.left=Math.min(b.width-110,Math.max(110,ev.clientX-b.left))+"px";t.style.top=(ev.clientY-b.top)+"px";t.classList.toggle("below",ev.clientY-b.top<b.height/2);t.classList.add("on")}
function updateMap(ips){
 const groups=new Map();
 for(const r of ips){if(r.lat==null||r.lon==null)continue;const k=r.lat.toFixed(1)+","+r.lon.toFixed(1);let g=groups.get(k);
  if(!g){g={lat:r.lat,lon:r.lon,cc:r.cc,city:r.city,region:r.region,country:r.country,ips:[],conn:0,ok:0,last:""};groups.set(k,g)}
  g.ips.push(r);g.conn+=r.connexions;g.ok+=r.reussies;if(r.last>g.last)g.last=r.last}
 const list=[...groups.values()].sort((a,b)=>b.conn-a.conn);
 const sig=list.map(g=>g.lat+g.lon+":"+g.conn+":"+g.ok+":"+g.ips.length).join("|")+Math.floor(Date.now()/6e4);
 const geoN=ips.filter(r=>r.lat!=null).length;
 $("#map-sub").textContent=nf.format(list.length)+" emplacement"+(list.length>1?"s":"")+" · "+nf.format(geoN)+" IP géolocalisée"+(geoN>1?"s":"");
 map.empty.textContent=last&&!last.geo?"Base de géolocalisation absente (voir README)":list.length?"":"Aucune IP géolocalisée pour l'instant";
 if(sig===map.sig)return;map.sig=sig;
 const max=Math.max(1,...list.map(g=>g.conn)),now=Date.now();
 map.dots.replaceChildren(...list.map(g=>{const p=svg("g",{class:"pt"+(g.ok?" ok":"")}),x=mx(g.lon),y=my(g.lat),r=3.5+10*Math.sqrt(g.conn/max);
  if(now-new Date(g.last)<15*6e4)p.append(svg("circle",{class:"p",cx:x,cy:y,r}));
  p.append(svg("circle",{class:"c",cx:x,cy:y,r}));
  p.addEventListener("mousemove",ev=>mapTip(g,ev));
  p.addEventListener("click",()=>{if(g.ips.length===1)return openIp(g.ips[0].ip);$("#ipfilter").value=g.city||countryOf(g);renderIps();
   $("#iptable").closest(".card").scrollIntoView({behavior:"smooth",block:"start"})});
  return p}))}

/* ---------- Tableau des IP ---------- */
const IPCOLS=[["pays","Origine",""],["ip","IP",""],["org","Réseau (AS)",""],["connexions","Connexions","num"],["tentatives","Tentatives","num"],
 ["reussies","Réussis","num"],["commandes","Commandes","num"],["last","Dernière activité",""]];
let ipSort={k:"last",dir:-1};const IP_ROWS=300;
const ipKey=(r,k)=>k==="pays"?countryOf(r)+" "+(r.city||""):k==="org"?(r.org||""):k==="ip"?r.ip.split(/[.:]/).map(p=>p.padStart(5,"0")).join("."):r[k];
function renderIps(){if(!last)return;const q=$("#ipfilter").value.trim().toLowerCase(),all=last.ips||[];
 let rows=q?all.filter(r=>[r.ip,countryOf(r),r.city,r.region,r.org,r.asn?"as"+r.asn:""].some(v=>v&&String(v).toLowerCase().includes(q))):all.slice();
 rows.sort((a,b)=>{const x=ipKey(a,ipSort.k),y=ipKey(b,ipSort.k);return(x>y?1:x<y?-1:0)*ipSort.dir});
 const thead=el("thead"),hr=el("tr");
 IPCOLS.forEach(([k,h,c])=>{const th=el("th","sort "+c+(ipSort.k===k?" on"+(ipSort.dir>0?" asc":""):""),h);
  th.onclick=()=>{ipSort=ipSort.k===k?{k,dir:-ipSort.dir}:{k,dir:k==="pays"||k==="ip"||k==="org"?1:-1};renderIps()};hr.append(th)});thead.append(hr);
 const tb=el("tbody");
 if(!rows.length){const tr=el("tr"),td=el("td");td.colSpan=IPCOLS.length;td.append(emptyBox(q?"Aucune IP pour ce filtre":"Rien pour l'instant"));tr.append(td);tb.append(tr)}
 rows.slice(0,IP_ROWS).forEach(r=>{const tr=el("tr");tr.onclick=()=>openIp(r.ip);
  const loc=el("td","loc"),top=el("span","iptag");top.append(flag(r.cc),countryOf(r));loc.append(top);if(r.city)loc.append(el("small","",r.city));
  const org=el("td","org",r.asn?"AS"+r.asn+(r.org?" · "+r.org:""):(r.org||"—"));org.title=org.textContent;
  const num=(v,ok)=>{const td=el("td","num"+(v?"":" zero"));if(ok&&v)td.append(el("span","pill ko",nf.format(v)));else td.textContent=nf.format(v);return td};
  const lt=el("td","t",ago(r.last));lt.title=fmtTime(r.last);
  tr.append(loc,el("td","mono",r.ip),org,num(r.connexions),num(r.tentatives),num(r.reussies,true),num(r.commandes),lt);tb.append(tr)});
 $("#iptable").replaceChildren(thead,tb);
 const tot=last.ips_total||all.length;
 $("#ip-sub").textContent=(q?nf.format(rows.length)+" sur ":"")+nf.format(tot)+" IP"+(rows.length>IP_ROWS?" · "+IP_ROWS+" affichées":"")+" · cliquer sur une ligne pour voir la fiche"}
$("#ipfilter").addEventListener("input",renderIps);

/* ---------- Fiche d'une IP ---------- */
let curIp=null;
const LINKS=[["AbuseIPDB","https://www.abuseipdb.com/check/"],["Shodan","https://www.shodan.io/host/"],["VirusTotal","https://www.virustotal.com/gui/ip-address/"],
 ["GreyNoise","https://viz.greynoise.io/ip/"],["Censys","https://search.censys.io/hosts/"],["ipinfo","https://ipinfo.io/"]];
function closeIp(){curIp=null;$("#drawer").classList.remove("open");$("#scrim").classList.remove("open");$("#drawer").setAttribute("aria-hidden","true")}
$("#scrim").onclick=closeIp;document.addEventListener("keydown",e=>{if(e.key==="Escape"&&curIp)closeIp()});
function openIp(ip){curIp=ip;const d=$("#drawer");d.classList.add("open");$("#scrim").classList.add("open");d.setAttribute("aria-hidden","false");
 const w=el("div","dw");for(let i=0;i<6;i++){const s=el("div","skel");s.style.height=i?"40px":"28px";w.append(s)}d.replaceChildren(w);d.scrollTop=0;loadIp()}
async function loadIp(){const ip=curIp;if(!ip)return;
 try{const r=await fetch("/api/ip/"+encodeURIComponent(ip),{cache:"no-store"});if(!r.ok)throw new Error(r.status);const d=await r.json();
  if(curIp===ip)renderIp(d)}catch(e){if(curIp===ip){const w=el("div","dw");w.append(emptyBox("Impossible de charger la fiche de "+ip));$("#drawer").replaceChildren(w)}}}
function btn(ic,label,fn){const b=el("button","btn");b.type="button";b.append(icon(ic),label);b.onclick=fn;return b}
function renderIp(d){const box=$("#drawer"),st=box.scrollTop,w=el("div","dw");
 /* en-tête */
 const h=el("div","dw-h"),t=el("div");t.append(el("h3","",d.ip),el("p","",placeOf(d)||"Localisation inconnue"));
 const x=el("button","btn icon");x.type="button";x.title="Fermer (Échap)";x.append(icon("x"));x.onclick=closeIp;h.append(flag(d.cc,"lg"),t,x);
 const act=el("div","dw-act");act.append(btn("copy","Copier l'IP",()=>copy(d.ip)),
  btn("filter","Filtrer le flux",()=>{$("#filter").value=d.ip;renderFeed(false);closeIp();$("#feed").closest(".card").scrollIntoView({behavior:"smooth"})}));
 /* chiffres */
 const mini=el("div","mini");[["connexions","Connexions"],["sessions","Sessions"],["tentatives","Tentatives"],["reussies","Logins réussis"],["commandes","Commandes"],["fichiers","Fichiers"]]
  .forEach(([k,l])=>{const c=el("div");c.append(el("b","",nf.format(d[k]||0)),el("small","",l));mini.append(c)});
 /* informations */
 const sec=(title,...nodes)=>{const s=el("section");s.append(el("h4","",title),...nodes);return s};
 const info=el("dl","info");const row=(k,v)=>{if(v===""||v==null)return;const dd=el("dd");if(v instanceof Node)dd.append(v);else dd.textContent=String(v);info.append(el("dt","",k),dd)};
 const cn=el("span","iptag");cn.append(flag(d.cc),countryOf(d)+(d.cc?" ("+d.cc.toUpperCase()+")":""));
 row("Pays",cn);row("Ville",d.city);row("Région",d.region);row("Continent",d.continent);
 row("ASN",d.asn?"AS"+d.asn:"");row("Organisation",d.org);
 row("Coordonnées",d.lat!=null?d.lat.toFixed(3)+", "+d.lon.toFixed(3)+" (approx.)":"");
 row("Première vue",fmtTime(d.first)+" · "+ago(d.first));row("Dernière vue",fmtTime(d.last)+" · "+ago(d.last));
 row("Clients SSH",(d.clients||[]).map(c=>c.label).join(", "));row("Type",d.private?"Adresse privée / locale":"Adresse publique");
 w.append(h,act,mini,sec("Informations",info));
 /* identifiants */
 if(d.credentials&&d.credentials.length){const tw=el("div","tw"),tb=el("table"),th=el("thead"),tr=el("tr");["Utilisateur","Mot de passe","Essais",""].forEach(x=>tr.append(el("th","",x)));th.append(tr);
  const body=el("tbody");d.credentials.forEach(c=>{const r=el("tr"),p=el("td");p.append(el("span",c.ok?"pill ok":"pill ko",c.ok?"Réussi":"Échec"));
   r.append(el("td","code",c.user===""?"(vide)":c.user),el("td","code",c.password===""?"(vide)":c.password),el("td","num",nf.format(c.count)),p);body.append(r)});
  tb.append(th,body);tw.append(tb);tw.style.maxHeight="260px";w.append(sec("Identifiants essayés",tw))}
 /* sessions */
 if(d.session_list&&d.session_list.length){const wrap=el("div");d.session_list.forEach(s=>{const c=el("div","sess"),hd=el("div","sess-h");
   hd.append(el("b","",fmtTime(s.start)));if(s.protocol)hd.append(el("span","",s.protocol.toUpperCase()+(s.port?" :"+s.port:"")));
   if(s.duration!=null)hd.append(el("span","","durée "+fmtDur(s.duration)));if(s.client)hd.append(el("span","",s.client));
   hd.append(el("span","",(s.id||"").slice(0,8)));c.append(hd);
   const b=el("div","sess-b");s.logins.forEach(l=>b.append(el("div","l"+(l.ok?" ok":""),(l.ok?"✔ login ":"✘ login ")+(l.user||"(vide)")+" / "+(l.password||"(vide)"))));
   s.commands.forEach(x=>b.append(el("div","c",x.input)));s.files.forEach(f=>b.append(el("div","l","↓ "+f.url)));
   if(!b.childNodes.length)b.append(el("div","l","Connexion sans authentification"));c.append(b);wrap.append(c)});
  w.append(sec("Sessions ("+nf.format(d.sessions)+")",wrap))}
 /* fichiers */
 if(d.files&&d.files.length){const tw=el("div","tw"),tb=el("table"),body=el("tbody");
  d.files.forEach(f=>{const r=el("tr"),hash=el("td","code");
   if(/^[a-f0-9]{64}$/i.test(f.sha256)){const a=el("a","",f.sha256);a.href="https://www.virustotal.com/gui/file/"+f.sha256;a.target="_blank";a.rel="noopener noreferrer";a.style.color="var(--info)";hash.append(a)}else hash.textContent=f.sha256||"—";
   r.append(el("td","t",fmtTime(f.ts)),el("td","code",f.url),hash);body.append(r)});tb.append(body);tw.append(tb);w.append(sec("Fichiers",tw))}
 /* liens externes (ouverts seulement sur clic) */
 if(!d.private){const l=el("div","links");LINKS.forEach(([n,u])=>{const a=el("a","btn");a.href=u+encodeURIComponent(d.ip);a.target="_blank";a.rel="noopener noreferrer";a.append(icon("ext"),n);l.append(a)});
  w.append(sec("Rechercher cette IP",l))}
 box.replaceChildren(w);box.scrollTop=st}

/* ---------- Flux d'événements ---------- */
const FEEDS={
 commands:{title:"Commandes",head:["Heure","IP","Session","Commande"],key:r=>r.ts+r.ip+r.input,
  cells:r=>[[fmtTime(r.ts),"t"],[r.ip,"ip",r.cc],[(r.session||"").slice(0,8),"sess"],[r.input,"code cmd"]]},
 logins:{title:"Connexions",head:["Heure","IP","Utilisateur","Mot de passe","Résultat"],key:r=>r.ts+r.ip+r.user+r.password,
  cells:r=>[[fmtTime(r.ts),"t"],[r.ip,"ip",r.cc],[r.user,"code"],[r.password,"code"],[r.ok?"Réussi":"Échec",r.ok?"pill ok":"pill ko"]]},
 files:{title:"Fichiers",head:["Heure","IP","URL / fichier","SHA-256"],key:r=>r.ts+r.ip+r.url,
  cells:r=>[[fmtTime(r.ts),"t"],[r.ip,"ip",r.cc],[r.url,"code"],[r.sha256,"code"]]},
};
let tab=localStorage.getItem("tab")||"commands";if(!FEEDS[tab])tab="commands";
const seen={},tabCount={};
$("#tabs").replaceChildren(...Object.entries(FEEDS).map(([k,f])=>{const b=el("button","tab"+(k===tab?" on":""),f.title);b.dataset.k=k;tabCount[k]=el("em","","0");b.append(tabCount[k]);
 b.onclick=()=>{tab=k;localStorage.setItem("tab",k);document.querySelectorAll(".tab").forEach(t=>t.classList.toggle("on",t.dataset.k===k));renderFeed(false)};return b}));
$("#filter").addEventListener("input",()=>renderFeed(false));
function renderFeed(markNew){
 const f=FEEDS[tab],rows=last?last[tab]:[],q=$("#filter").value.trim().toLowerCase(),t=$("#feed");
 if(!last)return;
 if(!seen[tab]){seen[tab]=new Set(rows.map(f.key));markNew=false}
 const fresh=new Set(markNew?rows.map(f.key).filter(k=>!seen[tab].has(k)):[]);rows.forEach(r=>seen[tab].add(f.key(r)));
 const shown=q?rows.filter(r=>f.cells(r).some(([v])=>String(v).toLowerCase().includes(q))):rows;
 const thead=el("thead"),hr=el("tr");f.head.forEach(h=>hr.append(el("th","",h)));thead.append(hr);
 const tb=el("tbody");
 if(!shown.length){const tr=el("tr"),td=el("td");td.colSpan=f.head.length;td.append(emptyBox(q?"Aucun résultat pour ce filtre":"Rien pour l'instant"));tr.append(td);tb.append(tr)}
 shown.forEach(r=>{const tr=el("tr");if(fresh.has(f.key(r)))tr.className="new";
  f.cells(r).forEach(([v,c,cc])=>{let td;if(c&&c.startsWith("pill")){td=el("td");td.append(el("span",c,v))}else if(c==="ip"){td=el("td","ip");td.append(ipTag(v,cc));td.onclick=()=>openIp(v)}else{td=el("td",c||"",v)}tr.append(td)});tb.append(tr)});
 t.replaceChildren(thead,tb)}

/* ---------- Boucle d'actualisation ---------- */
let last=null,timer=null,paused=false;
function setStatus(cls,text){const s=$("#status");s.className="status"+(cls?" "+cls:"");$("#live").textContent=text}
async function refresh(){
 try{const r=await fetch("/api/stats",{cache:"no-store"});if(!r.ok)throw new Error(r.status);const d=await r.json();
  const prev=last;last=d;
  updateKpis(d.totals);drawChart(d.per_hour);updateDonut(d.totals.reussies,d.totals.tentatives);
  RANKS.forEach(([k,,,ip])=>updateRank(k,d[k]||[],ip));
  updateCountries(d.top_countries||[]);updateMap(d.ips||[]);renderIps();if(curIp&&prev)loadIp();
  Object.keys(FEEDS).forEach(k=>{tabCount[k].textContent=d[k].length});
  renderFeed(!!prev);
  if(!paused)setStatus("","En direct · "+new Date().toLocaleTimeString("fr-FR"));
 }catch(e){setStatus("err","Impossible de lire les données")}}
function setPaused(p){paused=p;clearInterval(timer);$("#pause").replaceChildren(icon(p?"play":"pause"),p?"Reprendre":"Pause");
 if(p)setStatus("paused","En pause");else{refresh();timer=setInterval(refresh,REFRESH_MS)}}
$("#pause").onclick=()=>setPaused(!paused);
document.addEventListener("visibilitychange",()=>{if(!document.hidden&&!paused)refresh()});
setPaused(false);
</script></body></html>"""


@app.get("/")
def index():
    return Response(PAGE, mimetype="text/html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
