#!/usr/bin/env bash
# Démonstration : affiche les derniers messages TELS QU'ILS SONT STOCKÉS sur le serveur.
# On y voit l'expéditeur, le salon et l'heure (métadonnées), mais seulement du texte chiffré.
#
#   ./outils/ce-que-voit-le-serveur.sh                 5 derniers messages
#   ./outils/ce-que-voit-le-serveur.sh "jeudi"         cherche un mot dans TOUTE la base
set -euo pipefail
cd "$(dirname "$0")/.."
psql() { docker compose exec -T postgres psql -U synapse -d synapse -At "$@"; }

if [ -n "${1:-}" ]; then
  mot="${1//\'/\'\'}"
  n=$(psql -c "SELECT count(*) FROM event_json WHERE json ILIKE '%${mot}%'")
  echo "Le mot « $1 » apparaît dans $n événement(s) stocké(s) sur le serveur."
  exit 0
fi

psql -c "
SELECT to_char(to_timestamp(e.origin_server_ts / 1000), 'DD/MM HH24:MI') || '  ' ||
       e.sender || '  ' || e.type || E'\n    algorithme : ' ||
       coalesce(j.json::json->'content'->>'algorithm', '—') || E'\n    contenu    : ' ||
       left(coalesce(j.json::json->'content'->>'ciphertext', j.json::json->>'content'), 90) || '…'
FROM events e JOIN event_json j USING (event_id)
WHERE e.type IN ('m.room.encrypted', 'm.room.message')
ORDER BY e.stream_ordering DESC LIMIT 5"
