#!/usr/bin/env python3
"""Applique la liste des IP bannies (écrite par le panel) au pare-feu de l'hôte.

Tourne sur le VPS (pas dans Docker), lancé par systemd quand bans/banlist.json change.

Pourquoi nftables et pas `ufw deny` : Docker publie ses ports (22/23 du honeypot) en
passant devant UFW, donc un ban UFW ne bloquerait pas l'attaquant. Ici on utilise une
table dédiée `inet honeypot_ban`, accrochée en prerouting avec la priorité la plus haute
(-300) : le paquet est jeté avant Docker et avant UFW. La table est entièrement
reconstruite à chaque passage, en une seule transaction atomique.

Garde-fous : jamais d'IP privée/réservée, jamais une IP de la liste blanche
(bans/allowlist.txt), jamais l'IP d'une session SSH d'admin ouverte au moment du ban.
"""
import ipaddress
import json
import os
import subprocess
import sys
import time

BANS_DIR = os.environ.get("HONEYPOT_BANS", "/root/honeypot/bans")
BANLIST = os.path.join(BANS_DIR, "banlist.json")
APPLIED = os.path.join(BANS_DIR, "applied.json")
ALLOWLIST = os.path.join(BANS_DIR, "allowlist.txt")
TABLE = "honeypot_ban"


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def admin_ssh_peers():
    """IP connectées en ce moment au vrai SSH de l'hôte (on ne s'enferme jamais dehors)."""
    ports = set()
    for line in run(["sshd", "-T"]).stdout.splitlines():
        if line.startswith("port "):
            ports.add(line.split()[1])
    peers = set()
    for line in run(["ss", "-Htn", "state", "established"]).stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local, peer = parts[-2], parts[-1]
        if local.rsplit(":", 1)[-1] in ports:
            peers.add(peer.rsplit(":", 1)[0].strip("[]").removeprefix("::ffff:"))
    return peers


def allowlist():
    out = set()
    try:
        with open(ALLOWLIST, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    out.add(line)
    except OSError:
        pass
    return out


def write_applied(data):
    data["ts"] = time.time()
    tmp = APPLIED + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, APPLIED)


def main():
    try:
        with open(BANLIST, encoding="utf-8") as f:
            wanted = json.load(f)
    except FileNotFoundError:
        wanted = {}
    except ValueError as e:
        write_applied({"applied": [], "skipped": {}, "error": f"banlist.json illisible : {e}"})
        return 1

    protected_peers, allowed = admin_ssh_peers(), allowlist()
    v4, v6, skipped = [], [], {}
    for raw in wanted:
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            skipped[raw] = "adresse invalide"
            continue
        ip = str(addr)
        if not addr.is_global:
            skipped[raw] = "IP privée ou réservée"
        elif ip in allowed:
            skipped[raw] = "IP dans la liste blanche (allowlist.txt)"
        elif ip in protected_peers:
            skipped[raw] = "IP d'une session SSH d'admin ouverte : refusé pour ne pas te bloquer"
        else:
            (v4 if addr.version == 4 else v6).append(ip)

    def set_def(name, typ, ips):
        elems = f" elements = {{ {', '.join(ips)} }};" if ips else ""
        return f"  set {name} {{ type {typ};{elems} }}\n"

    script = (
        f"table inet {TABLE} {{}}\n"          # crée la table si besoin…
        f"delete table inet {TABLE}\n"        # …pour pouvoir la supprimer sans erreur
        f"table inet {TABLE} {{\n"            # puis la recréer à l'identique de la liste
        + set_def("v4", "ipv4_addr", v4)
        + set_def("v6", "ipv6_addr", v6)
        + "  chain prerouting {\n"
        "    type filter hook prerouting priority -300; policy accept;\n"
        "    ip saddr @v4 counter drop\n"
        "    ip6 saddr @v6 counter drop\n"
        "  }\n"
        "}\n"
    )
    res = run(["nft", "-f", "-"], input=script)
    if res.returncode != 0:
        write_applied({"applied": [], "skipped": skipped, "error": res.stderr.strip()[:300]})
        print(res.stderr, file=sys.stderr)
        return 1
    write_applied({"applied": v4 + v6, "skipped": skipped, "error": ""})
    print(f"{len(v4) + len(v6)} IP bloquées, {len(skipped)} refusées")
    return 0


if __name__ == "__main__":
    sys.exit(main())
