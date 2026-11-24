"""Géolocalisation hors ligne (DB-IP Lite) : aucune IP n'est envoyée à un service externe."""
import ipaddress
import math
import os
import re
from functools import lru_cache

try:
    import maxminddb
except ImportError:  # le panel marche aussi sans géolocalisation
    maxminddb = None

ASSETS = os.environ.get("PANEL_ASSETS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets"))
CC_RE = re.compile(r"[a-z]{2}")


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
ENABLED = CITY_DB is not None


def _tab_coord(s):
    """'+4851+00220' ou '+404251-0740023' (zone.tab) -> (lat, lon) en degrés."""
    i = max(s.rfind("+"), s.rfind("-"))
    out = []
    for part in (s[:i], s[i:]):
        sign, digits = (-1 if part[0] == "-" else 1), part[1:]
        n = 2 if len(digits) in (4, 6) else 3  # degrés sur 2 chiffres (lat) ou 3 (lon)
        d, rest = int(digits[:n]), digits[n:]
        out.append(sign * (d + int(rest[:2]) / 60 + (int(rest[2:4]) / 3600 if len(rest) > 2 else 0)))
    return out[0], out[1]


def _load_zones():
    """Fuseaux IANA avec le pays et la position de leur ville de référence (fichiers tzdata)."""
    dirs = ["/usr/share/zoneinfo"]
    try:
        import tzdata  # paquet pip installé dans l'image : ne dépend pas du système
        dirs.insert(0, os.path.join(os.path.dirname(tzdata.__file__), "zoneinfo"))
    except ImportError:
        pass
    for path in (os.path.join(d, n) for d in dirs for n in ("zone.tab", "zone1970.tab")):
        try:
            with open(path, encoding="utf-8") as f:
                zones = []
                for line in f:
                    if line.startswith("#") or not line.strip():
                        continue
                    cols = line.rstrip("\n").split("\t")
                    if len(cols) >= 3:
                        lat, lon = _tab_coord(cols[1])
                        zones.append((set(cols[0].lower().split(",")), lat, lon, cols[2]))
                if zones:
                    return zones
        except (OSError, ValueError, IndexError):
            continue
    return []


ZONES = _load_zones()


def timezone_of(cc, lat, lon):
    """Fuseau le plus probable : ville de référence la plus proche, dans le même pays si possible."""
    if lat is None or lon is None or not ZONES:
        return ""
    cands = [z for z in ZONES if cc in z[0]] or ZONES
    if len(cands) == 1:
        return cands[0][3]
    rl, rn = math.radians(lat), math.radians(lon)

    def dist(z):  # angle central (formule de haversine)
        zl, zn = math.radians(z[1]), math.radians(z[2])
        return math.sin((zl - rl) / 2) ** 2 + math.cos(rl) * math.cos(zl) * math.sin((zn - rn) / 2) ** 2
    best = min(cands, key=dist)[3]
    return ALIASES.get(best, best)


# Fuseaux d'enclaves, plus proches de certaines grandes villes que le fuseau principal du pays
# (Francfort tomberait sur Büsingen) : on affiche le fuseau principal, aux horaires identiques.
ALIASES = {"Europe/Busingen": "Europe/Berlin"}


def _name(node, lang="fr"):
    names = (node or {}).get("names") or {}
    return names.get(lang) or names.get("en") or ""


@lru_cache(maxsize=65536)
def _geo(ip):
    info = {"cc": "", "country": "", "city": "", "region": "", "continent": "",
            "lat": None, "lon": None, "tz": "", "asn": None, "org": "", "private": False}
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
        info["tz"] = timezone_of(info["cc"], info["lat"], info["lon"])
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
