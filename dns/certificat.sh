#!/bin/bash
# Lancé par certbot après chaque obtention ou renouvellement du certificat dns.soleiljaune.be.
# Technitium ne lit que le format .pfx : ce script le fabrique à partir des fichiers Let's Encrypt.
# Technitium repère le nouveau fichier tout seul en moins d'une minute, sans redémarrage.
set -euo pipefail

DOSSIER=/root/protego/dns
LE=/etc/letsencrypt/live/dns.soleiljaune.be
source "$DOSSIER/.env"

mkdir -p "$DOSSIER/config"
openssl pkcs12 -export \
  -inkey "$LE/privkey.pem" -in "$LE/fullchain.pem" \
  -out "$DOSSIER/config/dns.soleiljaune.be.pfx.tmp" \
  -passout "pass:$PFX_MOTDEPASSE"
chmod 600 "$DOSSIER/config/dns.soleiljaune.be.pfx.tmp"
# Remplacement en une fois, pour que Technitium ne lise jamais un fichier à moitié écrit
mv "$DOSSIER/config/dns.soleiljaune.be.pfx.tmp" "$DOSSIER/config/dns.soleiljaune.be.pfx"
echo "Certificat converti pour Technitium : $DOSSIER/config/dns.soleiljaune.be.pfx"
