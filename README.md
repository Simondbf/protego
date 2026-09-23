# Protego

Serveur DNS filtrant personnel, joignable en DNS chiffré (DNS-over-TLS) à l'adresse `dns.soleiljaune.be`.
Il tourne sur le VPS Hetzner avec [Technitium DNS Server](https://technitium.com/dns/).

## Les listes

| Fichier | Rôle |
|---|---|
| `liste-blocage.txt` | Domaines bloqués (un par ligne ; sous-domaines compris) |
| `liste-exceptions.txt` | Domaines toujours autorisés, même si une liste les bloque |

Technitium relit ces deux fichiers sur GitHub toutes les 2 heures : il suffit de les modifier ici.
S'y ajoute la liste publique [HaGeZi NSFW](https://github.com/hagezi/dns-blocklists), elle aussi mise à jour automatiquement.

SafeSearch forcé : Google, Bing, DuckDuckGo. YouTube n'est pas restreint.

## Fichiers du serveur (`dns/`)

| Fichier | Rôle |
|---|---|
| `docker-compose.yml` | Conteneur Technitium : port 853 public, console web sur `127.0.0.1:5380` |
| `nginx.conf` | Site nginx de `dns.soleiljaune.be`, uniquement pour la validation Let's Encrypt |
| `certificat.sh` | Crochet certbot : convertit le certificat en `.pfx` pour Technitium |
| `configurer.sh` | Configure Technitium par son API (DoT, listes, SafeSearch) ; se relance sans risque |
| `verifier.sh` | Vérifie filtrage, exceptions, SafeSearch et DNS chiffré |

Les secrets (`dns/.env`) et les données de Technitium (`dns/config/`) restent sur le serveur, hors de Git.

## Console web

Depuis le PC : `ssh -L 5380:127.0.0.1:5380 root@178.105.235.106`, puis ouvrir http://localhost:5380.
Identifiant `admin`, mot de passe : `grep TECHNITIUM_ADMIN /root/protego/dns/.env` sur le serveur.

## Téléphone Android

Paramètres → DNS privé → Nom d'hôte du fournisseur : `dns.soleiljaune.be`

## Ancienne version

`src/`, `schema.sql`, `wrangler.toml` et `GUIDE_DEPLOIEMENT.md` sont l'ancienne interface Cloudflare Worker (AdGuard Home sur Oracle Cloud, domaine rpisimon.uk). Ils seront supprimés une fois Cloudflare abandonné.
