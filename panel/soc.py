"""Vue « SOC » : bilan de l'exposition du honeypot depuis sa mise en ligne.

Tout est calculé à partir de la base SQLite (aucune donnée externe) :
durée en ligne, rythme des attaques, tendance, niveau de menace, « premières fois »,
journal des incidents classés par gravité, opérateurs et continents les plus actifs.
"""
from collections import Counter
from datetime import datetime, timedelta, timezone

import store
import tags

# Gravité des comportements détectés (tags.py) dans le journal des incidents.
TAG_SEVERITY = {
    "miner": "critique", "botnet": "critique", "persist": "critique",
    "download": "haute", "exec": "haute", "accounts": "haute", "cleanup": "haute", "redis": "haute",
    "detect": "moyenne",
}
SEV_ORDER = {"critique": 0, "haute": 1, "moyenne": 2, "action": 3}
MILESTONE_COUNTS = (100, 1000, 10000, 100000, 1000000)


def _dt(ts):
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%S")


def compute(con, geo, bans):
    one = lambda sql, a=(): con.execute(sql, a).fetchone()[0]  # noqa: E731
    first = one("SELECT MIN(ts) FROM events")
    if not first:
        return {"empty": True}
    now = datetime.now(timezone.utc)
    t0 = _dt(first) or now
    uptime = max(1.0, (now - t0).total_seconds())
    after = lambda ts: round(((_dt(ts) or now) - t0).total_seconds())  # noqa: E731

    # ---------- Totaux ----------
    totals = {
        "connexions": one("SELECT COUNT(*) FROM events WHERE kind='connect'"),
        "ips": one("SELECT COUNT(DISTINCT ip) FROM events WHERE kind='connect'"),
        "tentatives": one(f"SELECT COUNT(*) FROM events WHERE kind IN {store.LOGIN_KINDS}"),
        "reussies": one("SELECT COUNT(*) FROM events WHERE kind='login_ok'"),
        "ips_reussies": one("SELECT COUNT(DISTINCT ip) FROM events WHERE kind='login_ok'"),
        "commandes": one("SELECT COUNT(*) FROM events WHERE kind='command'"),
        "fichiers": one("SELECT COUNT(*) FROM events WHERE kind='file'"),
        "fichiers_uniques": one("SELECT COUNT(DISTINCT shasum) FROM events WHERE kind='file' AND shasum IS NOT NULL"),
        "revenues": one("""SELECT COUNT(*) FROM (SELECT ip FROM events WHERE kind='connect' GROUP BY ip
                           HAVING COUNT(DISTINCT substr(ts,1,10)) > 1)"""),
        "bannies": len(bans),
        "bannies_auto": sum(1 for b in bans if b.get("auto")),
    }

    # ---------- Fenêtres récentes et tendance ----------
    def window(h_from, h_to=0):
        a, b = _iso(now - timedelta(hours=h_from)), _iso(now - timedelta(hours=h_to)) if h_to else "9999"
        r = con.execute("""SELECT SUM(kind='connect'), COUNT(DISTINCT CASE WHEN kind='connect' THEN ip END),
                                  SUM(kind='login_ok'), SUM(kind='command')
                           FROM events WHERE ts >= ? AND ts < ?""", (a, b)).fetchone()
        return {"connexions": r[0] or 0, "ips": r[1] or 0, "reussies": r[2] or 0, "commandes": r[3] or 0}
    last1, last24, prev24 = window(1), window(24), window(48, 24)
    new_ips_24h = one("SELECT COUNT(*) FROM (SELECT ip FROM events WHERE kind='connect' GROUP BY ip HAVING MIN(ts) >= ?)",
                      (_iso(now - timedelta(hours=24)),))

    # ---------- Par jour (UTC) ----------
    new_by_day = dict(con.execute("""SELECT d, COUNT(*) FROM (SELECT ip, MIN(substr(ts,1,10)) d FROM events
                                     WHERE kind='connect' GROUP BY ip) GROUP BY d"""))
    days = [{"day": r[0], "connexions": r[1] or 0, "ips": r[2] or 0, "tentatives": r[3] or 0,
             "reussies": r[4] or 0, "commandes": r[5] or 0, "nouvelles_ips": new_by_day.get(r[0], 0)}
            for r in con.execute(f"""SELECT substr(ts,1,10) d, SUM(kind='connect'),
                    COUNT(DISTINCT CASE WHEN kind='connect' THEN ip END), SUM(kind IN {store.LOGIN_KINDS}),
                    SUM(kind='login_ok'), SUM(kind='command') FROM events GROUP BY d ORDER BY d""")]
    busiest = max(days, key=lambda d: d["connexions"]) if days else None
    peak_hour = con.execute("""SELECT substr(ts,1,13) h, COUNT(*) c FROM events WHERE kind='connect'
                               GROUP BY h ORDER BY c DESC LIMIT 1""").fetchone()

    # ---------- Surface d'attaque (par service) ----------
    services = []
    for r in con.execute("""SELECT sensor, COALESCE(protocol,'') p, COUNT(*) c, COUNT(DISTINCT ip) i
                            FROM events WHERE kind='connect' GROUP BY sensor, p ORDER BY c DESC"""):
        name = {"ssh": "SSH", "telnet": "Telnet", "redis": "Redis"}.get(r["p"], r["p"] or r["sensor"])
        port = {"ssh": 22, "telnet": 23, "redis": 6379}.get(r["p"])
        services.append({"name": name, "sensor": r["sensor"], "port": port, "connexions": r["c"], "ips": r["i"]})

    # ---------- Premières fois ----------
    milestones = []

    def add(kind_label, row, detail=""):
        if row and row["ts"]:
            milestones.append({"label": kind_label, "ts": row["ts"], "after": after(row["ts"]), "ip": row["ip"] or "",
                               "cc": geo(row["ip"])["cc"] if row["ip"] else "", "detail": detail})
    first_of = lambda kind: con.execute(  # noqa: E731
        "SELECT * FROM events WHERE kind=? ORDER BY ts LIMIT 1", (kind,)).fetchone()
    add("Mise en ligne · première connexion reçue", first_of("connect") or {"ts": first, "ip": None})
    r = con.execute(f"SELECT * FROM events WHERE kind IN {store.LOGIN_KINDS} ORDER BY ts LIMIT 1").fetchone()
    add("Première tentative de login", r, f"{r['username'] or ''} / {r['password'] or ''}" if r else "")
    r = first_of("login_ok")
    add("Premier bot connecté", r, f"{r['username'] or ''} / {r['password'] or ''}" if r else "")
    r = first_of("command")
    add("Première commande", r, (r["input"] or "")[:120] if r else "")
    r = first_of("file")
    add("Premier fichier déposé", r, (r["url"] or "")[:160] if r else "")
    for t, ts, ip in con.execute("""SELECT t.tag, MIN(e.ts), e.ip FROM tags t JOIN events e ON e.session = t.session
                                    WHERE t.tag IN ('miner','botnet','persist','redis') GROUP BY t.tag"""):
        add("Premier comportement : " + tags.LABELS.get(t, t), {"ts": ts, "ip": ip})
    for n in MILESTONE_COUNTS:
        if totals["connexions"] < n:
            break
        r = con.execute("SELECT ts, ip FROM events WHERE kind='connect' ORDER BY ts LIMIT 1 OFFSET ?", (n - 1,)).fetchone()
        add(f"{n:,}e connexion".replace(",", " "), r)
    milestones.sort(key=lambda m: m["ts"])

    # ---------- Journal des incidents ----------
    incidents = []
    for r in con.execute("SELECT ts, ip, session, username, password FROM events WHERE kind='login_ok' ORDER BY id DESC LIMIT 60"):
        incidents.append({"ts": r["ts"], "sev": "haute", "type": "Login réussi", "ip": r["ip"] or "",
                          "detail": f"{r['username'] or ''} / {r['password'] or ''}"})
    for r in con.execute("SELECT ts, ip, url FROM events WHERE kind='file' ORDER BY id DESC LIMIT 60"):
        incidents.append({"ts": r["ts"], "sev": "critique", "type": "Fichier déposé", "ip": r["ip"] or "",
                          "detail": r["url"] or ""})
    for r in con.execute("""SELECT t.tag, t.ip, MIN(e.ts) ts FROM tags t JOIN events e ON e.session = t.session
                            GROUP BY t.session, t.tag ORDER BY ts DESC LIMIT 200"""):
        sev = TAG_SEVERITY.get(r["tag"])
        if sev:
            incidents.append({"ts": r["ts"], "sev": sev, "type": tags.LABELS.get(r["tag"], r["tag"]),
                              "ip": r["ip"] or "", "detail": ""})
    for b in bans:
        incidents.append({"ts": b.get("ts", ""), "sev": "action", "type": "IP bannie" + (" (auto)" if b.get("auto") else ""),
                          "ip": b.get("ip", ""), "detail": b.get("reason", "")})
    for i in incidents:
        i["cc"] = geo(i["ip"])["cc"] if i["ip"] else ""
    incidents.sort(key=lambda i: str(i["ts"]), reverse=True)
    since24 = _iso(now - timedelta(hours=24))
    since1 = _iso(now - timedelta(hours=1))
    sev24 = Counter(i["sev"] for i in incidents if str(i["ts"]) >= since24)

    # ---------- Opérateurs et continents ----------
    asn, cont = Counter(), Counter()
    asn_name = {}
    for ip, c in con.execute("SELECT ip, COUNT(*) FROM events WHERE kind='connect' GROUP BY ip"):
        gi = geo(ip)
        if gi.get("asn"):
            key = gi["asn"]
            asn[key] += 1
            asn_name[key] = (gi.get("org") or "", gi.get("cc") or "")
        cont[gi.get("continent") or "Inconnu"] += 1
    top_asn = [{"asn": k, "org": asn_name[k][0], "cc": asn_name[k][1], "ips": v} for k, v in asn.most_common(8)]
    countries = len({geo(ip)["cc"] for (ip,) in con.execute("SELECT DISTINCT ip FROM events WHERE kind='connect'")} - {""})

    # ---------- Niveau de menace ----------
    hourly_avg = totals["connexions"] / (uptime / 3600)
    ratio = last1["connexions"] / max(hourly_avg, 0.1)
    crit_1h = any(i["sev"] == "critique" and str(i["ts"]) >= since1 for i in incidents)
    if crit_1h:
        level, why = "critique", "comportement critique détecté dans la dernière heure"
    elif sev24.get("critique") or ratio >= 2:
        level, why = "élevé", ("comportement critique dans les dernières 24 h" if sev24.get("critique")
                               else f"activité {ratio:.1f}× au-dessus de la moyenne")
    elif ratio >= 0.5 or sev24.get("haute"):
        level, why = "modéré", "activité habituelle d'Internet (scans et essais de mots de passe)"
    else:
        level, why = "faible", "activité inférieure à la moyenne"

    return {
        "now": now.isoformat(timespec="seconds"),
        "online_since": t0.isoformat(timespec="seconds"),
        "uptime": round(uptime),
        "totals": {**totals, "pays": countries},
        "rates": {"per_hour": round(hourly_avg, 1), "per_day": round(totals["connexions"] / (uptime / 86400), 1),
                  "every_s": round(uptime / totals["connexions"], 1) if totals["connexions"] else None,
                  "login_success": round(100 * totals["reussies"] / totals["tentatives"], 1) if totals["tentatives"] else 0},
        "last1h": last1, "last24h": {**last24, "nouvelles_ips": new_ips_24h}, "prev24h": prev24,
        "threat": {"level": level, "why": why, "ratio": round(ratio, 2), "incidents_24h": dict(sev24)},
        "days": days,
        "busiest_day": busiest,
        "peak_hour": {"hour": peak_hour[0] + ":00:00Z", "connexions": peak_hour[1]} if peak_hour else None,
        "services": services,
        "milestones": milestones,
        "incidents": incidents[:150],
        "top_asn": top_asn,
        "continents": [{"name": k, "ips": v} for k, v in cont.most_common()],
    }
