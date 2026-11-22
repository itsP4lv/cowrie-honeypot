"""Lecture des enregistrements d'écran de Cowrie (var/lib/cowrie/tty/<sha256>).

Format Cowrie : une suite d'enregistrements, chacun avec un en-tête
struct "<iLiiLL" (op, tty, longueur, direction, secondes, microsecondes)
suivi de `longueur` octets. op 3 = écriture ; direction 1 = entrée, 2 = sortie.
"""
import os
import re
import struct

TTY_DIR = os.path.join(os.environ.get("COWRIE_DATA", "/data"), "lib", "cowrie", "tty")
HEADER = struct.Struct("<iLiiLL")
OP_WRITE, DIR_INPUT, DIR_OUTPUT = 3, 1, 2
MAX_BYTES = 4 * 1024 * 1024
MAX_FRAMES = 20000
NAME_RE = re.compile(r"[0-9a-f]{64}")


def path_for(ttylog):
    """Le chemin vient des logs : on ne garde que le nom (hash) et on refuse tout le reste."""
    name = os.path.basename(str(ttylog or ""))
    if not NAME_RE.fullmatch(name):
        return None
    p = os.path.join(TTY_DIR, name)
    return p if os.path.isfile(p) else None


def frames(path):
    """Renvoie [[ms depuis le début, direction, texte], …] et un indicateur de troncature."""
    out, t0, truncated = [], None, False
    with open(path, "rb") as f:
        data = f.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        data, truncated = data[:MAX_BYTES], True
    pos = 0
    while pos + HEADER.size <= len(data):
        op, _tty, length, direction, sec, usec = HEADER.unpack_from(data, pos)
        pos += HEADER.size
        if length < 0 or pos + length > len(data):
            truncated = True
            break
        chunk = data[pos:pos + length]
        pos += length
        if op != OP_WRITE or direction not in (DIR_INPUT, DIR_OUTPUT) or not chunk:
            continue
        t = sec * 1000 + usec // 1000
        if t0 is None:
            t0 = t
        out.append([max(0, t - t0), direction, chunk.decode("utf-8", "replace")])
        if len(out) >= MAX_FRAMES:
            truncated = True
            break
    return out, truncated
