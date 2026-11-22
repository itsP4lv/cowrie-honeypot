"""Réputation VirusTotal des fichiers capturés (optionnel : VT_API_KEY dans .env).

On n'envoie QUE le SHA-256 (recherche), jamais le fichier : un malware déposé sur un
honeypot peut contenir des informations sur la cible, on ne le partage pas.
Rythme : 1 requête toutes les 20 s (la clé gratuite autorise 4/min et 500/jour).
"""
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import store

API_KEY = os.environ.get("VT_API_KEY", "").strip()
ENABLED = bool(re.fullmatch(r"[0-9a-f]{64}", API_KEY))
SHA_RE = re.compile(r"[0-9a-f]{64}")
RECHECK_NOT_FOUND = timedelta(days=1)  # un fichier inconnu peut être soumis par d'autres plus tard


def lookup(sha):
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha}",
                                 headers={"x-apikey": API_KEY, "User-Agent": "honeypot-panel"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            attr = json.load(r)["data"]["attributes"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "inconnu", "malicious": None, "total": None, "label": ""}
        raise
    stats = attr.get("last_analysis_stats") or {}
    label = ((attr.get("popular_threat_classification") or {}).get("suggested_threat_label") or "")[:80]
    return {"status": "ok", "malicious": int(stats.get("malicious", 0)),
            "total": int(sum(v for v in stats.values() if isinstance(v, int))), "label": label}


def _next(con):
    limit = (datetime.now(timezone.utc) - RECHECK_NOT_FOUND).isoformat()
    for r in con.execute("""SELECT DISTINCT lower(e.shasum) AS sha FROM events e
                             LEFT JOIN vt ON vt.sha256 = lower(e.shasum)
                             WHERE e.kind='file' AND e.shasum IS NOT NULL
                               AND (vt.sha256 IS NULL OR (vt.status='inconnu' AND vt.checked < ?))
                             LIMIT 20""", (limit,)):
        if SHA_RE.fullmatch(r["sha"] or ""):
            return r["sha"]
    return None


def _worker(ready):
    ready.wait()
    con = store.connect()
    while True:
        try:
            sha = _next(con)
            if sha:
                res = lookup(sha)
                with con:
                    con.execute("INSERT OR REPLACE INTO vt(sha256, checked, status, malicious, total, label) VALUES (?,?,?,?,?,?)",
                                (sha, datetime.now(timezone.utc).isoformat(), res["status"], res["malicious"], res["total"], res["label"]))
        except Exception as exc:  # noqa: BLE001
            print("VirusTotal :", type(exc).__name__, exc if not isinstance(exc, urllib.error.HTTPError) else exc.code, flush=True)
        time.sleep(20)


def start(ready):
    if ENABLED:
        threading.Thread(target=_worker, args=(ready,), daemon=True, name="virustotal").start()
    elif API_KEY:
        print("VirusTotal : VT_API_KEY invalide (64 caractères hexadécimaux attendus), ignoré", flush=True)
