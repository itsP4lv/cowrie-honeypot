# Ajouter un honeypot

Le panel est prêt à recevoir d'autres honeypots que Cowrie. Chaque événement est rangé dans SQLite avec le nom du honeypot qui l'a produit (`sensor`). Ajouter un honeypot se fait en 5 étapes :

1. le lancer dans Docker, à côté de Cowrie ;
2. ouvrir ses ports ;
3. donner au panel l'accès à ses logs, en lecture seule ;
4. écrire un **parseur** de 20 lignes qui traduit ses logs en événements du panel ;
5. vérifier.

Le bouton « Bannir » marche automatiquement pour tous les honeypots, car le ban jette les paquets avant Docker.

---

## 0. Avant de commencer

**Choisir le honeypot.** Le VPS a 2 Go de RAM, dont environ 500 Mo utilisés aujourd'hui. Il faut donc des honeypots légers :

| Honeypot | Ce qu'il imite | Intérêt |
|---|---|---|
| **Dionaea** | SMB, FTP, HTTP, MSSQL, MySQL, TFTP, SIP… | capture des **malwares** (vers SMB type WannaCry, botnets) |
| **Heralding** | FTP, Telnet, POP3, IMAP, SMTP, PostgreSQL, MySQL, RDP, VNC… | collecte les **identifiants** essayés sur plein de protocoles |
| Un honeypot web léger (faux WordPress, faux panneau d'admin…) | HTTP | scans de failles web, tentatives de login |
| ~~T-Pot~~ | tout | trop gros pour ce VPS (il demande 8 Go de RAM ou plus) |

Pour commencer, je conseille **Dionaea** : les malwares capturés alimentent directement la colonne VirusTotal du panel.

**Vérifier les ressources et les ports déjà pris :**
```bash
free -m          # RAM disponible
df -h /          # espace disque
ss -tlnp         # ports déjà utilisés : 22 et 23 (Cowrie), ton port SSH d'admin, 127.0.0.1:8080 (panel)
```

> ⚠️ Ne publie **jamais** sur un honeypot le port de ton SSH d'admin.

---

## 1. Ajouter le service dans `docker-compose.yml`

Modèle à adapter. Les noms exacts de l'image, des dossiers de logs et des ports viennent de la documentation du honeypot choisi :

```yaml
  dionaea:
    image: dinotools/dionaea:latest        # vérifier l'image officielle dans la doc
    container_name: dionaea
    restart: unless-stopped
    ports:
      - "21:21"       # FTP
      - "445:445"     # SMB
      - "3306:3306"   # MySQL
      # n'expose que les services que tu veux vraiment observer
    volumes:
      - dionaea-var:/opt/dionaea/var       # logs + fichiers capturés (chemin selon la doc)
    # Durcissement (comme pour le panel)
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]            # écouter sur des ports < 1024
    security_opt:
      - no-new-privileges:true
    mem_limit: 384m
    pids_limit: 256
```
puis dans la section `volumes:` en bas du fichier :
```yaml
  dionaea-var:
```

**Règles de sécurité à ne jamais enfreindre pour un honeypot :**
- ❌ jamais `privileged: true` ;
- ❌ jamais `network_mode: host` ;
- ❌ jamais monter `/var/run/docker.sock`, car ça donnerait le contrôle total du VPS à un attaquant qui s'échapperait du honeypot ;
- ❌ jamais monter un dossier de l'hôte comme `/root` ou `/etc` ;
- ✅ un volume Docker dédié par honeypot ;
- ✅ une limite de mémoire, pour qu'un honeypot saturé ne fasse pas tomber le VPS.

> Si le honeypot doit **accepter de vraies connexions entrantes de malwares** (Dionaea télécharge les payloads), il a besoin d'accès sortant à Internet, et c'est normal. Les fichiers capturés restent dans son volume : ne les exécute jamais.

Lance-le et regarde ses logs :
```bash
docker compose up -d dionaea
docker compose logs -f dionaea
```

---

## 2. Ouvrir les ports

Docker publie les ports **sans passer par UFW** : dès que `ports:` est dans le compose, le port est ouvert sur Internet. Ajoute quand même les règles UFW, pour que `ufw status` reste une liste fidèle de ce qui est exposé :
```bash
ufw allow 21/tcp  comment "honeypot Dionaea FTP"
ufw allow 445/tcp comment "honeypot Dionaea SMB"
ufw allow 3306/tcp comment "honeypot Dionaea MySQL"
```

Vérifie depuis **ton PC** (pas depuis le VPS) :
```bash
nmap -Pn -p 21,445,3306 IP_DU_VPS
```
> Certains fournisseurs d'accès bloquent des ports en sortie (23, 25, 445…). Un port « fermé » depuis chez toi n'est pas forcément fermé pour le reste d'Internet.

---

## 3. Donner au panel l'accès aux logs

Dans le service `panel` du `docker-compose.yml`, ajoute le volume du honeypot **en lecture seule** :
```yaml
    volumes:
      - cowrie-var:/data:ro
      - dionaea-var:/data-dionaea:ro      # ← nouveau
```

Il faut que le honeypot écrive ses logs en **JSON, une ligne par événement**. C'est le cas de Cowrie, de Heralding (`log_session.json`) et de Dionaea, à condition d'activer son module de log JSON (voir sa doc).

Pour voir à quoi ressemble une ligne :
```bash
docker run --rm -v honeypot_dionaea-var:/v:ro alpine sh -c 'tail -n 3 /v/<chemin>/<fichier>.json'
```

---

## 4. Écrire le parseur (`panel/store.py`)

Le panel comprend 7 types d'événements (`kind`) :

| `kind` | Signification | Champs utiles |
|---|---|---|
| `connect` | nouvelle connexion | `protocol`, `dst_port` |
| `login_ok` / `login_fail` | tentative d'identification | `username`, `password` |
| `command` | commande tapée | `input` |
| `file` | fichier capturé | `url`, `shasum` (SHA-256) |
| `client` | logiciel client annoncé | `version` |
| `closed` | fin de session | `duration` (secondes) |

Chaque événement a aussi `ts` (date ISO 8601 en UTC), `ip` (IP de l'attaquant) et `session` (un identifiant pour regrouper les événements d'une même connexion).

Ajoute une fonction qui transforme **une ligne JSON du honeypot** en événement du panel. Par exemple, pour un honeypot dont les lignes ressemblent à
`{"timestamp": "...", "src_ip": "1.2.3.4", "connection": {"protocol": "ftp", "local_port": 21}, "credentials": {"username": "admin", "password": "123"}}` :

```python
def parse_dionaea(e):
    """À adapter aux vrais noms de champs (regarde quelques lignes de log d'abord)."""
    base = {
        "ts": e.get("timestamp", ""),
        "ip": e.get("src_ip"),
        "session": str(e.get("connection", {}).get("id") or e.get("timestamp")),
    }
    conn = e.get("connection") or {}
    creds = e.get("credentials") or {}
    if creds.get("username") is not None:
        return {**base, "kind": "login_fail", "username": creds.get("username"), "password": creds.get("password")}
    if e.get("download_sha256"):
        return {**base, "kind": "file", "url": e.get("download_url"), "shasum": e.get("download_sha256")}
    return {**base, "kind": "connect", "protocol": conn.get("protocol"), "dst_port": conn.get("local_port")}
```

Puis déclare la source dans la liste `SOURCES`, en haut du fichier :
```python
SOURCES = [
    {"sensor": "cowrie", "glob": os.path.join(DATA, "log", "cowrie", "cowrie.json*"), "parse": parse_cowrie},
    {"sensor": "dionaea", "glob": "/data-dionaea/<chemin>/*.json*", "parse": parse_dionaea},
]
```

À savoir :
- Le parseur ne doit **jamais planter** : utilise `e.get(...)` partout. Une ligne illisible est simplement ignorée.
- Les valeurs sont automatiquement tronquées (4 000 caractères) et insérées avec des requêtes SQL paramétrées : pas de risque d'injection, même si l'attaquant met n'importe quoi dans ses identifiants.
- Une ligne ne peut donner qu'un seul événement. Si le honeypot écrit une ligne par session avec tout dedans, le plus simple est de produire l'événement le plus important (`login`, sinon `file`, sinon `connect`).
- Au premier démarrage, le panel importe tout l'historique du nouveau honeypot, puis lit les nouvelles lignes au fil de l'eau.

**Étiquettes de comportement** : si le honeypot enregistre des commandes, `panel/tags.py` les classe automatiquement. Pour ajouter une règle, il suffit d'une ligne dans `RULES`.

---

## 5. Redéployer et vérifier

```bash
cd /root/honeypot
docker compose up -d --build panel
docker compose logs -f panel        # pas d'erreur « ingestion : … »
```

Dans le panel :
- en bas de page, « **Honeypots : cowrie, dionaea** » ;
- les nouvelles IP apparaissent dans la liste, la carte et les classements ;
- dans la fiche d'une IP, les sessions du nouveau honeypot portent son nom.

Pour tester toi-même depuis ton PC (ton IP apparaîtra dans le panel) :
```bash
ftp IP_DU_VPS          # essaie admin / admin
```

---

## Récapitulatif sécurité

- [ ] Aucun `privileged`, `network_mode: host` ni socket Docker monté
- [ ] Un volume dédié, et monté en lecture seule (`:ro`) dans le panel
- [ ] Limite de mémoire (`mem_limit`) et de processus (`pids_limit`)
- [ ] Port de ton SSH d'admin jamais réutilisé
- [ ] Ports ajoutés à UFW pour garder `ufw status` fidèle
- [ ] Panel toujours sur `127.0.0.1:8080` seulement
- [ ] Interface d'administration du honeypot, s'il en a une, **jamais** publiée sur Internet : `127.0.0.1:` devant le port, comme le panel
