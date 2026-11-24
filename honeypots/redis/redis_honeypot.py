#!/usr/bin/env python3
"""Faux serveur Redis (honeypot à faible interaction).

Il parle le protocole Redis (RESP) comme un vrai Redis 7 ouvert sans mot de passe,
répond de façon crédible aux commandes courantes, et enregistre tout ce que les
attaquants envoient dans un fichier JSON (une ligne par événement), lu par le panel.

Ce qu'il ne fait JAMAIS :
  - exécuter quoi que ce soit, écrire sur le disque (hors son log) ou charger un module ;
  - se connecter vers l'extérieur : « SLAVEOF ip port » (attaque classique pour
    pousser un module malveillant) répond +OK mais aucune connexion n'est ouverte.

Garde-fous : taille des commandes bornée, nombre de connexions et de commandes limité,
déconnexion après inactivité, données stockées en mémoire plafonnées.
"""
import asyncio
import json
import os
import secrets
import time
from datetime import datetime, timezone

PORT = int(os.environ.get("REDIS_HP_PORT", "6379"))
LOG_DIR = os.environ.get("REDIS_HP_LOG_DIR", "/var/log/redis-hp")
LOG_FILE = os.path.join(LOG_DIR, "redis.json")
LOG_MAX = 50 * 1024 * 1024        # rotation du log à 50 Mo (redis.json -> redis.json.1)
MAX_CLIENTS = 200                 # connexions simultanées
MAX_ARGS = 64                     # arguments par commande
MAX_BULK = 64 * 1024              # taille max d'un argument
MAX_CMDS = 1000                   # commandes par connexion
IDLE = 120                        # secondes sans rien recevoir -> déconnexion
MAX_KEYS = 500                    # clés gardées en mémoire (partagées entre connexions)

START = time.time()
VERSION = "7.0.15"
RUN_ID = secrets.token_hex(20)

# Quelques clés crédibles, comme sur un serveur de cache d'application web
STORE = {
    "session:7f3a9c1e2b": "{\"user_id\":42,\"role\":\"editor\"}",
    "session:c81d44a09f": "{\"user_id\":7,\"role\":\"admin\"}",
    "cache:homepage": "<html>…</html>",
    "queue:mail:pending": "3",
    "config:maintenance": "0",
}
CONFIG = {"dir": "/var/lib/redis", "dbfilename": "dump.rdb", "maxmemory": "0", "appendonly": "no",
          "save": "3600 1 300 100 60 10000", "bind": "0.0.0.0", "protected-mode": "no", "port": str(PORT),
          "requirepass": "", "databases": "16"}
clients = 0


# ---------- Journal ----------
def log(event, **fields):
    rec = {"eventid": f"redis.{event}", "timestamp": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
           "sensor": "redis", **fields}
    try:
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > LOG_MAX:
            os.replace(LOG_FILE, LOG_FILE + ".1")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as exc:
        print("log :", exc, flush=True)


# ---------- Protocole RESP ----------
class ProtocolError(Exception):
    """Message renvoyé au client : mêmes textes que le vrai Redis, pour ne pas se trahir."""


async def read_command(reader):
    """Lit une commande : tableau RESP (*2\r\n$4\r\nPING…) ou commande « inline » (PING\r\n)."""
    line = await reader.readline()
    if not line:
        return None
    if len(line) > MAX_BULK:
        raise ProtocolError("too big inline request")
    line = line.rstrip(b"\r\n")
    if not line.startswith(b"*"):
        return line.split()  # commande inline (telnet, nc…)
    try:
        n = int(line[1:])
    except ValueError:
        raise ProtocolError("invalid multibulk length") from None
    if n < 0 or n > MAX_ARGS:
        raise ProtocolError("invalid multibulk length")
    args = []
    for _ in range(n):
        hdr = (await reader.readline()).rstrip(b"\r\n")
        if not hdr.startswith(b"$"):
            raise ProtocolError("expected '$', got something else")
        try:
            size = int(hdr[1:])
        except ValueError:
            raise ProtocolError("invalid bulk length") from None
        if size < 0 or size > MAX_BULK:
            raise ProtocolError("invalid bulk length")
        data = await reader.readexactly(size + 2)
        args.append(data[:-2])
    return args


def simple(s):
    return f"+{s}\r\n".encode()


def error(s):
    return f"-{s}\r\n".encode()


def integer(n):
    return f":{n}\r\n".encode()


def bulk(v):
    if v is None:
        return b"$-1\r\n"
    b = v if isinstance(v, bytes) else str(v).encode()
    return b"$%d\r\n%s\r\n" % (len(b), b)


def array(items):
    return b"*%d\r\n" % len(items) + b"".join(bulk(i) for i in items)


def info_text():
    up = int(time.time() - START)
    return "\r\n".join([
        "# Server", f"redis_version:{VERSION}", "redis_git_sha1:00000000", "redis_git_dirty:0",
        "redis_mode:standalone", "os:Linux 6.1.0-28-amd64 x86_64", "arch_bits:64", "multiplexing_api:epoll",
        "gcc_version:12.2.0", "process_id:812", f"run_id:{RUN_ID}", f"tcp_port:{PORT}",
        f"uptime_in_seconds:{up + 1987654}", f"uptime_in_days:{(up + 1987654) // 86400}",
        "executable:/usr/bin/redis-server", "config_file:/etc/redis/redis.conf", "",
        "# Clients", f"connected_clients:{clients}", "blocked_clients:0", "",
        "# Memory", "used_memory:1245184", "used_memory_human:1.19M", "maxmemory:0", "maxmemory_policy:noeviction", "",
        "# Persistence", "loading:0", "rdb_changes_since_last_save:3", "rdb_last_bgsave_status:ok", "aof_enabled:0", "",
        "# Replication", "role:master", "connected_slaves:0", "",
        "# Keyspace", f"db0:keys={len(STORE)},expires=2,avg_ttl=0", "",
    ]) + "\r\n"


def handle(args):
    """Renvoie (réponse, fermer_la_connexion)."""
    cmd = args[0].decode("utf-8", "replace").lower()
    a = [x.decode("utf-8", "replace") for x in args[1:]]
    if cmd == "ping":
        return (bulk(a[0]) if a else simple("PONG")), False
    if cmd == "echo" and a:
        return bulk(a[0]), False
    if cmd == "quit":
        return simple("OK"), True
    if cmd == "auth":
        return error("ERR AUTH <password> called without any password configured for the default user. "
                     "Are you sure your configuration is correct?"), False
    if cmd == "hello":
        return error("NOPROTO unsupported protocol version"), False
    if cmd == "info":
        return bulk(info_text()), False
    if cmd in ("select", "flushall", "flushdb", "client", "save"):
        if cmd in ("flushall", "flushdb"):
            STORE.clear()
        if cmd == "client" and a and a[0].lower() == "list":
            return bulk("id=3 addr=127.0.0.1:52344 laddr=127.0.0.1:6379 fd=8 name= age=12 idle=0 flags=N db=0 cmd=client|list\n"), False
        return simple("OK"), False
    if cmd == "bgsave":
        return simple("Background saving started"), False
    if cmd == "dbsize":
        return integer(len(STORE)), False
    if cmd == "keys":
        return array(sorted(STORE)[:200]), False
    if cmd == "scan":
        return b"*2\r\n" + bulk("0") + array(sorted(STORE)[:200]), False
    if cmd == "type" and a:
        return simple("string" if a[0] in STORE else "none"), False
    if cmd == "get" and a:
        return bulk(STORE.get(a[0])), False
    if cmd in ("set", "setex", "setnx") and len(a) >= 2:
        key, val = a[0], a[-1]
        if key in STORE or len(STORE) < MAX_KEYS:
            STORE[key] = val[:4096]
        return (integer(1) if cmd == "setnx" else simple("OK")), False
    if cmd == "del" and a:
        return integer(sum(1 for k in a if STORE.pop(k, None) is not None)), False
    if cmd == "exists" and a:
        return integer(sum(1 for k in a if k in STORE)), False
    if cmd == "config" and a:
        sub = a[0].lower()
        if sub == "get" and len(a) >= 2:
            pat = a[1]
            items = []
            for k, v in CONFIG.items():
                if pat == "*" or pat == k:
                    items += [k, v]
            return array(items), False
        if sub == "set" and len(a) >= 3:
            if a[1].lower() in CONFIG:
                CONFIG[a[1].lower()] = a[2][:512]
            return simple("OK"), False
        if sub in ("resetstat", "rewrite"):
            return simple("OK"), False
    if cmd in ("slaveof", "replicaof"):
        return simple("OK"), False  # aucune connexion sortante n'est faite
    if cmd == "module":
        if a and a[0].lower() == "list":
            return b"*0\r\n", False
        return error("ERR Error loading the extension. Please check the server logs."), False
    if cmd in ("eval", "evalsha", "script", "function"):
        return error("NOSCRIPT No matching script. Please use EVAL."), False
    if cmd == "command":
        return b"*0\r\n", False
    if cmd == "time":
        t = time.time()
        return array([str(int(t)), str(int((t % 1) * 1e6))]), False
    if cmd == "lastsave":
        return integer(int(START)), False
    if cmd == "shutdown":
        return error("ERR Errors trying to SHUTDOWN. Check logs."), False
    first = (" ".join(f"'{x[:20]}'" for x in a[:3]) + " ") if a else ""
    return error(f"ERR unknown command '{args[0].decode('utf-8', 'replace')[:40]}', with args beginning with: {first}"), False


# ---------- Connexions ----------
async def on_client(reader, writer):
    global clients
    peer = writer.get_extra_info("peername") or ("?", 0)
    ip, port = peer[0], peer[1]
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    session = secrets.token_hex(6)
    t0 = time.time()
    if clients >= MAX_CLIENTS:
        writer.write(error("ERR max number of clients reached"))
        writer.close()
        return
    clients += 1
    log("connect", src_ip=ip, src_port=port, session=session, dst_port=PORT, protocol="redis")
    n = 0
    try:
        while n < MAX_CMDS:
            try:
                args = await asyncio.wait_for(read_command(reader), IDLE)
            except ProtocolError as exc:
                writer.write(error(f"ERR Protocol error: {exc}"))
                break
            if args is None:
                break
            if not args:
                continue
            n += 1
            text = " ".join(x.decode("utf-8", "replace") for x in args)
            log("command", src_ip=ip, session=session, input=text[:2000])
            reply, close = handle(args)
            writer.write(reply)
            await writer.drain()
            if close:
                break
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, ValueError):
        pass
    finally:
        clients -= 1
        log("closed", src_ip=ip, session=session, duration=round(time.time() - t0, 2))
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    server = await asyncio.start_server(on_client, host="0.0.0.0", port=PORT, limit=MAX_BULK + 16)
    print(f"faux Redis {VERSION} en écoute sur le port {PORT}, log : {LOG_FILE}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
