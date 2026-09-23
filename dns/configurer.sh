#!/bin/bash
# Configure Technitium par son API : DNS chiffré, listes de blocage mises à jour
# automatiquement, SafeSearch forcé (Google, Bing, DuckDuckGo ; YouTube laissé libre).
# Se relance sans risque : chaque réglage est simplement réécrit.
set -euo pipefail
cd "$(dirname "$0")"
source .env

API=http://127.0.0.1:5380/api
DEPOT=https://raw.githubusercontent.com/Simondbf/protego/main
# Le "!" devant une adresse en fait une liste d'exceptions (sites toujours autorisés)
LISTES="$DEPOT/liste-blocage.txt,!$DEPOT/liste-exceptions.txt,https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt"
MISE_A_JOUR_HEURES=2

statut_ok() { python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("status")=="ok" else 1)'; }

# api ROUTE [clé=valeur ...] : appelle l'API et s'arrête net si elle ne répond pas "ok"
api() {
  local route=$1; shift
  local args=(--data-urlencode "token=$JETON") kv reponse
  for kv in "$@"; do args+=(--data-urlencode "$kv"); done
  reponse=$(curl -sS -X POST "$API/$route" "${args[@]}")
  if ! statut_ok <<<"$reponse" 2>/dev/null; then
    echo "Échec de $route : $reponse" >&2
    return 1
  fi
}

if [[ ! -f config/dns.soleiljaune.be.pfx ]]; then
  echo "Certificat absent (config/dns.soleiljaune.be.pfx) : lance d'abord certbot." >&2
  exit 1
fi

echo "Connexion à Technitium..."
JETON=""
for _ in $(seq 1 30); do
  JETON=$(curl -sS -X POST "$API/user/login" --data-urlencode user=admin --data-urlencode "pass=$TECHNITIUM_ADMIN" 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["token"]) if d.get("status")=="ok" else sys.exit(1)' 2>/dev/null) && break
  JETON=""; sleep 2
done
if [[ -z $JETON ]]; then
  echo "Connexion impossible : le conteneur tourne-t-il (docker ps) ?" >&2
  exit 1
fi

echo "Réglages : DNS chiffré, récursion, blocage, listes..."
api settings/set \
  dnsServerDomain=dns.soleiljaune.be \
  recursion=Allow \
  enableDnsOverTls=true \
  dnsTlsCertificatePath=/etc/dns/dns.soleiljaune.be.pfx \
  "dnsTlsCertificatePassword=$PFX_MOTDEPASSE" \
  enableBlocking=true \
  blockingType=NxDomain \
  "blockListUrls=$LISTES" \
  "blockListUpdateIntervalHours=$MISE_A_JOUR_HEURES"
api settings/forceUpdateBlockLists

# SafeSearch : une zone par moteur, qui renvoie tout vers ce serveur sauf les noms qu'on y force
zone() {
  api zones/create zone="$1" type=Forwarder forwarder=this-server 2>/dev/null || true  # existe déjà : on continue
}
force() {  # force ZONE NOM TYPE clé=valeur
  api zones/records/add zone="$1" domain="$2" type="$3" "$4" ttl=3600 overwrite=true
}
echo "SafeSearch..."
for z in google.com google.fr google.be; do
  zone "$z"
  force "$z" "www.$z" CNAME cname=forcesafesearch.google.com
done
zone bing.com
force bing.com www.bing.com CNAME cname=strict.bing.com
zone duckduckgo.com
force duckduckgo.com duckduckgo.com ANAME aname=safe.duckduckgo.com
force duckduckgo.com www.duckduckgo.com CNAME cname=safe.duckduckgo.com

echo "Configuration terminée. Téléchargement des listes en cours, vérification dans 30 secondes..."
sleep 30
./verifier.sh
