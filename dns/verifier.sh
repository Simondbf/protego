#!/bin/bash
# Vérifie que le filtrage, les exceptions, le SafeSearch et le DNS chiffré fonctionnent.
# Se relance sans risque autant de fois que voulu.
set -uo pipefail

# teste NOM ATTENDU : interroge Technitium et compare avec le résultat attendu
teste() {
  local nom=$1 attendu=$2 r statut detail
  r=$(docker exec technitium dig @127.0.0.1 "$nom" +noall +comments +answer +time=5 2>&1)
  statut=$(grep -o 'status: [A-Z]*' <<<"$r" | cut -d' ' -f2)
  detail=$(grep -v '^;' <<<"$r" | grep -v '^$' | head -1 | awk '{print $4, $5}')
  if [[ $statut == "$attendu" || $detail == *"$attendu"* ]]; then res="OK   "; else res="ÉCHEC"; fi
  printf '%s %-22s %-9s %s\n' "$res" "$nom" "$statut" "$detail"
}

echo "=== Filtrage (NXDOMAIN attendu) ==="
teste pornhub.com NXDOMAIN        # liste publique HaGeZi
teste japscan.com NXDOMAIN        # ta liste
teste qwant.com NXDOMAIN          # ta liste (moteurs de recherche)
echo "=== Exceptions et sites normaux (NOERROR attendu) ==="
teste webtoons.com NOERROR
teste twitch.tv NOERROR
teste wikipedia.org NOERROR
echo "=== SafeSearch ==="
teste www.google.com forcesafesearch.google.com.
teste www.google.fr forcesafesearch.google.com.
teste www.bing.com strict.bing.com.
teste www.duckduckgo.com safe.duckduckgo.com.
teste www.youtube.com NOERROR     # YouTube volontairement non restreint

echo "=== DNS chiffré depuis Internet (port 853) ==="
r=$(docker exec technitium dig +tls @dns.soleiljaune.be qwant.com +noall +comments +time=5 2>&1)
if grep -q 'status: NXDOMAIN' <<<"$r"; then echo "OK    requête DoT filtrée"; else echo "ÉCHEC requête DoT : $(tail -3 <<<"$r")"; fi
echo | openssl s_client -connect dns.soleiljaune.be:853 -servername dns.soleiljaune.be -verify_return_error 2>/dev/null \
  | grep -E "^subject=|Verify return code" || echo "ÉCHEC : pas de réponse TLS sur le port 853"
