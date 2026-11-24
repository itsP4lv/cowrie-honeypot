"""Stockage SQLite des événements des honeypots, alimenté au fil de l'eau.

Avant : le panel relisait tous les logs JSON toutes les 5 s (de plus en plus lent).
Maintenant : un thread lit seulement les nouvelles lignes, les normalise et les insère
dans SQLite ; les pages et l'API font des requêtes SQL indexées.

Multi-honeypots : chaque source (SOURCES) a un nom de capteur (`sensor`), un motif de
fichiers et une fonction `parse` qui transforme une ligne en événement normalisé.
Ajouter un honeypot = ajouter une source (voir le README, « Ajouter un honeypot »).

Types d'événements normalisés (`kind`) :
  connect, login_ok, login_fail, command, file, client, closed
"""
import glob
import json
import os
import socket
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

import tags

DATA = os.environ.get("COWRIE_DATA", "/data")
STATE = os.environ.get("PANEL_STATE", "/state")
DB_PATH = os.path.join(STATE, "panel.db")
SCAN_EVERY = 2.0  # secondes


def _own_ips():
    """IP du conteneur du panel : la page de statut sonde les honeypots depuis ici,
    ces connexions ne doivent pas être comptées comme des attaques."""
    try:
        return {ai[4][0] for ai in socket.getaddrinfo(socket.gethostname(), None)}
    except OSError:
        return set()


OWN_IPS = _own_ips()


# ---------- Parseurs ----------
def parse_cowrie(e):
    eid = e.get("eventid", "")
    base = {"ts": e.get("timestamp", ""), "ip": e.get("src_ip"), "session": e.get("session")}
    if eid == "cowrie.session.connect":
        return {**base, "kind": "connect", "protocol": e.get("protocol"), "dst_port": e.get("dst_port")}
    if eid in ("cowrie.login.success", "cowrie.login.failed"):
        return {**base, "kind": "login_ok" if eid.endswith("success") else "login_fail",
                "username": e.get("username"), "password": e.get("password")}
    if eid == "cowrie.command.input":
        return {**base, "kind": "command", "input": e.get("input")}
    if eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
        return {**base, "kind": "file", "url": e.get("url") or e.get("filename"), "shasum": e.get("shasum")}
    if eid == "cowrie.client.version":
        return {**base, "kind": "client", "version": e.get("version")}
    if eid == "cowrie.session.closed":
        return {**base, "kind": "closed", "duration": e.get("duration")}
    if eid == "cowrie.log.closed":
        return {**base, "kind": "tty", "ttylog": e.get("ttylog")}
    return None  # événements sans intérêt pour le panel (kex, taille du terminal…)


def parse_redis(e):
    """Faux Redis (honeypots/redis) : mêmes types d'événements que Cowrie."""
    eid = e.get("eventid", "")
    base = {"ts": e.get("timestamp", ""), "ip": e.get("src_ip"), "session": e.get("session")}
    if eid == "redis.connect":
        return {**base, "kind": "connect", "protocol": "redis", "dst_port": e.get("dst_port")}
    if eid == "redis.command":
        return {**base, "kind": "command", "input": e.get("input")}
    if eid == "redis.closed":
        return {**base, "kind": "closed", "duration": e.get("duration")}
    return None


REDIS_DATA = os.environ.get("REDIS_DATA", "/data-redis")

SOURCES = [
    {"sensor": "cowrie", "glob": os.path.join(DATA, "log", "cowrie", "cowrie.json*"), "parse": parse_cowrie},
    {"sensor": "redis", "glob": os.path.join(REDIS_DATA, "redis.json*"), "parse": parse_redis},
    # Demain : {"sensor": "dionaea", "glob": "/data-dionaea/…", "parse": parse_dionaea},
]

COLUMNS = ("sensor", "ts", "kind", "ip", "session", "username", "password", "input",
           "url", "shasum", "version", "protocol", "dst_port", "duration", "ttylog")

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, sensor TEXT NOT NULL, ts TEXT NOT NULL, kind TEXT NOT NULL,
  ip TEXT, session TEXT, username TEXT, password TEXT, input TEXT, url TEXT, shasum TEXT,
  version TEXT, protocol TEXT, dst_port INTEGER, duration REAL, ttylog TEXT);
CREATE INDEX IF NOT EXISTS ev_kind_ts ON events(kind, ts);
CREATE INDEX IF NOT EXISTS ev_ip ON events(ip, ts);
CREATE INDEX IF NOT EXISTS ev_session ON events(session);
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
CREATE TABLE IF NOT EXISTS sources(inode INTEGER, path TEXT, sensor TEXT, offset INTEGER,
  PRIMARY KEY(sensor, inode));
CREATE TABLE IF NOT EXISTS tags(session TEXT, ip TEXT, tag TEXT, PRIMARY KEY(session, tag));
CREATE INDEX IF NOT EXISTS tags_ip ON tags(ip);
CREATE TABLE IF NOT EXISTS vt(sha256 TEXT PRIMARY KEY, checked TEXT, status TEXT,
  malicious INTEGER, total INTEGER, label TEXT);
"""


def _clean(v, n=4000):
    """Les valeurs viennent des attaquants : on borne leur taille et leur type."""
    if v is None:
        return None
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v
    return str(v)[:n]


def connect(readonly=False):
    os.makedirs(STATE, exist_ok=True)
    if readonly:
        con = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=10)
    else:
        con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    return con


class Ingester(threading.Thread):
    """Lit les nouvelles lignes des logs et les insère dans SQLite."""

    def __init__(self, on_event=None):
        super().__init__(daemon=True, name="ingester")
        self.on_event = on_event  # appelé pour chaque événement « en direct » (alertes)
        self.ready = threading.Event()  # rattrapage initial terminé

    def run(self):
        con = connect()
        con.executescript(SCHEMA)
        first = True
        while True:
            try:
                self.scan(con, live=not first)
            except Exception as exc:  # noqa: BLE001 - le thread ne doit jamais mourir
                print("ingestion :", exc, flush=True)
            if first:
                first = False
                self.ready.set()
            time.sleep(SCAN_EVERY)

    def scan(self, con, live):
        for src in SOURCES:
            for path in sorted(glob.glob(src["glob"])):
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                row = con.execute("SELECT offset FROM sources WHERE sensor=? AND inode=?",
                                  (src["sensor"], st.st_ino)).fetchone()
                offset = row["offset"] if row else 0
                if st.st_size < offset:  # fichier tronqué ou recréé
                    offset = 0
                if st.st_size == offset:
                    continue
                self.read_file(con, src, path, st.st_ino, offset, live)

    def read_file(self, con, src, path, inode, offset, live):
        batch, live_events = [], []
        with open(path, "rb") as f:
            f.seek(offset)
            while True:
                line = f.readline()
                if not line or not line.endswith(b"\n"):
                    break  # ligne incomplète : on la relira au prochain passage
                offset += len(line)
                try:
                    raw = json.loads(line)
                    ev = src["parse"](raw) if isinstance(raw, dict) else None
                except (ValueError, UnicodeDecodeError):
                    ev = None
                if not ev or not ev.get("ts") or not ev.get("kind") or ev.get("ip") in OWN_IPS:
                    continue
                ev["sensor"] = src["sensor"]
                batch.append(tuple(_clean(ev.get(c)) for c in COLUMNS))
                if ev["kind"] == "command" and ev.get("session"):
                    for t in tags.classify(str(ev.get("input") or "")):
                        con.execute("INSERT OR IGNORE INTO tags(session, ip, tag) VALUES (?,?,?)",
                                    (_clean(ev["session"], 64), _clean(ev.get("ip"), 64), t))
                if live:
                    live_events.append(ev)
                if len(batch) >= 2000:
                    self.flush(con, batch, src, path, inode, offset)
                    batch = []
        self.flush(con, batch, src, path, inode, offset)
        if self.on_event:
            for ev in live_events:
                try:
                    self.on_event(ev)
                except Exception as exc:  # noqa: BLE001
                    print("alerte :", exc, flush=True)

    @staticmethod
    def flush(con, batch, src, path, inode, offset):
        with con:
            if batch:
                con.executemany(f"INSERT INTO events({','.join(COLUMNS)}) VALUES ({','.join('?' * len(COLUMNS))})", batch)
            con.execute("INSERT OR REPLACE INTO sources(inode, path, sensor, offset) VALUES (?,?,?,?)",
                        (inode, path, src["sensor"], offset))


# ---------- Requêtes ----------
LOGIN_KINDS = "('login_ok','login_fail')"


def since_iso(hours):
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")


def top(con, sql, args=(), n=8):
    return [{"label": r[0] if r[0] is not None else "", "count": r[1]}
            for r in con.execute(sql + f" LIMIT {int(n)}", args)]


def ip_summaries(con, where="1=1", args=(), limit=None):
    sql = f"""
      SELECT ip, MIN(ts) AS first, MAX(ts) AS last,
        SUM(kind='connect') AS connexions, COUNT(DISTINCT session) AS sessions,
        SUM(kind IN {LOGIN_KINDS}) AS tentatives, SUM(kind='login_ok') AS reussies,
        SUM(kind='command') AS commandes, SUM(kind='file') AS fichiers,
        GROUP_CONCAT(DISTINCT sensor) AS sensors
      FROM events WHERE ip IS NOT NULL AND {where} GROUP BY ip ORDER BY last DESC"""
    if limit:
        sql += f" LIMIT {int(limit)}"
    return [dict(r) for r in con.execute(sql, args)]


def tags_by_ip(con, ips):
    out = {}
    ips = list(ips)
    for i in range(0, len(ips), 500):
        chunk = ips[i:i + 500]
        q = f"SELECT ip, tag FROM tags WHERE ip IN ({','.join('?' * len(chunk))})"
        for r in con.execute(q, chunk):
            out.setdefault(r["ip"], set()).add(r["tag"])
    return {k: sorted(v) for k, v in out.items()}
