"""Géolocalisation hors ligne (DB-IP Lite) : aucune IP n'est envoyée à un service externe."""
import ipaddress
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
