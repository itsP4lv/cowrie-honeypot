"""Panel web pour le honeypot Cowrie.

Lit les logs JSON de Cowrie et affiche les attaques en direct.
Toutes les données affichées viennent des attaquants : elles sont insérées
dans la page avec textContent (jamais innerHTML) pour éviter toute XSS.
"""
import glob
import json
import os
from collections import Counter
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, Response

DATA = os.environ.get("COWRIE_DATA", "/data")
LOG_GLOB = os.path.join(DATA, "log", "cowrie", "cowrie.json*")
DOWNLOADS = os.path.join(DATA, "lib", "cowrie", "downloads")

app = Flask(__name__)


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


@app.get("/api/stats")
def stats():
    events = read_events()
    logins = [e for e in events if e.get("eventid") in ("cowrie.login.failed", "cowrie.login.success")]
    success = [e for e in logins if e["eventid"] == "cowrie.login.success"]
    commands = [e for e in events if e.get("eventid") == "cowrie.command.input"]
    connects = [e for e in events if e.get("eventid") == "cowrie.session.connect"]
    clients = [e for e in events if e.get("eventid") == "cowrie.client.version"]
    files = [e for e in events if e.get("eventid") in ("cowrie.session.file_download", "cowrie.session.file_upload")]

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

    def top(counter, n=8):
        return [{"label": k, "count": v} for k, v in counter.most_common(n)]

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
        },
        "top_ips": top(ips),
        "top_users": top(users),
        "top_passwords": top(passwords),
        "top_combos": top(combos),
        "top_commands": top(top_cmds),
        "top_clients": top(versions),
        "per_hour": per_hour,
        "commands": [
            {"ts": e.get("timestamp", ""), "ip": e.get("src_ip", ""),
             "session": e.get("session", ""), "input": e.get("input", "")}
            for e in commands[-100:]
        ][::-1],
        "logins": [
            {"ts": e.get("timestamp", ""), "ip": e.get("src_ip", ""),
             "user": e.get("username", ""), "password": e.get("password", ""),
             "ok": e["eventid"] == "cowrie.login.success"}
            for e in logins[-100:]
        ][::-1],
        "files": [
            {"ts": e.get("timestamp", ""), "ip": e.get("src_ip", ""),
             "url": e.get("url") or e.get("filename", ""), "sha256": e.get("shasum", "")}
            for e in files[-50:]
        ][::-1],
    })


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
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:16px}
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

 <section class="grid" id="ranks"></section>

 <section class="card">
  <div class="card-h">
   <div class="tabs" id="tabs"></div>
   <label class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
    <input type="search" id="filter" placeholder="Filtrer (IP, commande, mot de passe…)" autocomplete="off"></label>
  </div>
  <div class="tw"><table id="feed"></table></div>
 </section>
</main>
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

/* ---------- Thème ---------- */
function applyTheme(t){document.documentElement.dataset.theme=t;$("#theme").replaceChildren(icon(t==="light"?"moon":"sun"));localStorage.setItem("theme",t)}
applyTheme(localStorage.getItem("theme")||(matchMedia("(prefers-color-scheme: light)").matches?"light":"dark"));
$("#theme").onclick=()=>{applyTheme(document.documentElement.dataset.theme==="light"?"dark":"light");if(last)drawChart(last.per_hour)};

/* ---------- KPI ---------- */
const KPIS=[
 ["connexions","Connexions","activity","var(--acc)"],
 ["ips_uniques","IP uniques","globe","var(--info)"],
 ["tentatives","Tentatives de login","key","var(--vio)"],
 ["reussies","Logins réussis","unlock","var(--ok)"],
 ["commandes","Commandes tapées","terminal","var(--acc2)"],
 ["fichiers","Fichiers capturés","file","var(--ko)"],
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
const RANKS=[["top_ips","Top IP attaquantes","cliquer pour copier",true],["top_combos","Top combinaisons","identifiant / mot de passe"],
 ["top_users","Top identifiants",""],["top_passwords","Top mots de passe",""],["top_commands","Commandes les plus tapées",""],["top_clients","Clients SSH","version annoncée par l'attaquant"]];
const rankBoxes={};
$("#ranks").replaceChildren(...RANKS.map(([k,title,sub])=>{const c=el("div","card"),h=el("div","card-h"),h2=el("h2","",title);
 if(sub)h2.append(el("small","",sub));h.append(h2);const b=el("div","rank");for(let i=0;i<4;i++){const s=el("div","skel");s.style.margin="8px 0";b.append(s)}
 c.append(h,b);rankBoxes[k]=b;return c}));
function updateRank(k,rows,isIp){const box=rankBoxes[k];if(!rows.length)return box.replaceChildren(emptyBox());
 const max=Math.max(...rows.map(r=>r.count));
 box.replaceChildren(...rows.map((r,i)=>{const row=el("div","rk"+(isIp?" ip":"")),lb=el("div","lb"),tr=el("div","tr"),fill=el("i");
  fill.style.width=(r.count/max*100)+"%";tr.append(fill);const label=r.label===""?"(vide)":r.label;lb.append(el("span","",label),tr);lb.title=label;
  row.append(el("span","n",i+1),lb,el("span","ct",nf.format(r.count)));if(isIp)row.onclick=()=>copy(r.label);return row}))}

/* ---------- Flux d'événements ---------- */
const FEEDS={
 commands:{title:"Commandes",head:["Heure","IP","Session","Commande"],key:r=>r.ts+r.ip+r.input,
  cells:r=>[[fmtTime(r.ts),"t"],[r.ip,"ip"],[(r.session||"").slice(0,8),"sess"],[r.input,"code cmd"]]},
 logins:{title:"Connexions",head:["Heure","IP","Utilisateur","Mot de passe","Résultat"],key:r=>r.ts+r.ip+r.user+r.password,
  cells:r=>[[fmtTime(r.ts),"t"],[r.ip,"ip"],[r.user,"code"],[r.password,"code"],[r.ok?"Réussi":"Échec",r.ok?"pill ok":"pill ko"]]},
 files:{title:"Fichiers",head:["Heure","IP","URL / fichier","SHA-256"],key:r=>r.ts+r.ip+r.url,
  cells:r=>[[fmtTime(r.ts),"t"],[r.ip,"ip"],[r.url,"code"],[r.sha256,"code"]]},
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
  f.cells(r).forEach(([v,c])=>{let td;if(c&&c.startsWith("pill")){td=el("td");td.append(el("span",c,v))}else{td=el("td",c||"",v);if(c==="ip")td.onclick=()=>copy(v)}tr.append(td)});tb.append(tr)});
 t.replaceChildren(thead,tb)}

/* ---------- Boucle d'actualisation ---------- */
let last=null,timer=null,paused=false;
function setStatus(cls,text){const s=$("#status");s.className="status"+(cls?" "+cls:"");$("#live").textContent=text}
async function refresh(){
 try{const r=await fetch("/api/stats",{cache:"no-store"});if(!r.ok)throw new Error(r.status);const d=await r.json();
  const prev=last;last=d;
  updateKpis(d.totals);drawChart(d.per_hour);updateDonut(d.totals.reussies,d.totals.tentatives);
  RANKS.forEach(([k,,,ip])=>updateRank(k,d[k]||[],ip));
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
