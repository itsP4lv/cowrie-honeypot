"""Télécharge les données du panel au moment du build (aucun appel externe ensuite).

- DB-IP Lite City + ASN (CC BY 4.0) : géolocalisation hors ligne des IP
- world-atlas land-110m (Natural Earth, domaine public) : contour des continents
- flag-icons (MIT) : drapeaux SVG (Windows n'affiche pas les emojis drapeaux)

Usage : python fetch_assets.py [dossier]   (par défaut ./assets)
"""
import gzip
import io
import os
import sys
import tarfile
import urllib.request
from datetime import date

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "assets")
FLAGS_VERSION = "7.6.0"


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "honeypot-panel-build"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def months():
    """Mois courant puis précédent : la base du mois n'est publiée qu'en début de mois."""
    d = date.today()
    yield f"{d.year}-{d.month:02d}"
    y, m = (d.year, d.month - 1) if d.month > 1 else (d.year - 1, 12)
    yield f"{y}-{m:02d}"


def fetch_dbip(kind):
    dest = os.path.join(OUT, f"dbip-{kind}-lite.mmdb")
    for month in months():
        url = f"https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
        try:
            data = gzip.decompress(get(url))
        except Exception as e:  # noqa: BLE001
            print(f"  {url} : {e}")
            continue
        with open(dest, "wb") as f:
            f.write(data)
        print(f"  {dest} ({len(data) // 1024 // 1024} Mo, {month})")
        return
    print(f"  ATTENTION : base DB-IP {kind} indisponible, le panel tournera sans géolocalisation")


def fetch_map():
    dest = os.path.join(OUT, "land-110m.json")
    with open(dest, "wb") as f:
        f.write(get("https://cdn.jsdelivr.net/npm/world-atlas@2/land-110m.json"))
    print(f"  {dest}")


def fetch_flags():
    dest = os.path.join(OUT, "flags")
    os.makedirs(dest, exist_ok=True)
    tgz = get(f"https://registry.npmjs.org/flag-icons/-/flag-icons-{FLAGS_VERSION}.tgz")
    n = 0
    with tarfile.open(fileobj=io.BytesIO(tgz), mode="r:gz") as tar:
        for m in tar.getmembers():
            # package/flags/4x3/fr.svg  ->  flags/fr.svg (on ne garde que les codes à 2 lettres)
            parts = m.name.split("/")
            if m.isfile() and parts[1:3] == ["flags", "4x3"] and len(parts) == 4:
                name = parts[3]
                if len(name) == 6 and name.endswith(".svg") and name[:2].isalpha():
                    with open(os.path.join(dest, name.lower()), "wb") as f:
                        f.write(tar.extractfile(m).read())
                    n += 1
    print(f"  {dest} ({n} drapeaux)")


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    print("Téléchargement des données du panel…")
    fetch_dbip("city")
    fetch_dbip("asn")
    fetch_map()
    fetch_flags()
