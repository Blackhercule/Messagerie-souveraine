#!/usr/bin/env bash
# Installation de la messagerie souveraine en une commande.
#
#   ./installer.sh                     démonstration sur cet ordinateur (https://localhost:8443)
#   ./installer.sh 192.168.1.20        démonstration sur le réseau local (téléphones, autres PC)
#   ./installer.sh --changer-adresse 10.0.0.5
#                                      nouveau réseau (jour de la présentation) : GARDE les comptes,
#                                      les conversations et le certificat déjà installé sur les appareils
#   ./installer.sh --reinitialiser …   efface TOUTES les données et recommence de zéro
#
# Sous Windows : lancer ce script depuis « Git Bash », avec Docker Desktop démarré.
set -euo pipefail
# Git Bash (Windows) : ne pas transformer les chemins des conteneurs (« caddy:/data/… »).
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")"

adresse_valide() {  # une adresse IP ou un nom (lettres, chiffres, points, tirets)
  case "$1" in
    ""|*[!A-Za-z0-9.-]*) echo "Adresse invalide : « $1 » (exemple : 192.168.1.20)."; exit 1 ;;
  esac
}

CHANGEMENT_ADRESSE=""
if [ "${1:-}" = "--changer-adresse" ]; then
  [ -f .env ] || { echo "Aucune installation ici : lancez d'abord ./installer.sh ${2:-<adresse>}"; exit 1; }
  CHANGEMENT_ADRESSE="${2:-}"
  adresse_valide "$CHANGEMENT_ADRESSE"
  shift 2
fi

if [ "${1:-}" = "--reinitialiser" ]; then
  shift
  read -r -p "Toutes les conversations et tous les comptes seront effacés. Continuer ? (oui/non) " reponse
  [ "$reponse" = "oui" ] || exit 1
  docker compose down -v || true
  rm -f .env ca-messagerie.crt
fi

command -v docker >/dev/null || { echo "Docker est requis (Docker Desktop sous Windows et macOS)."; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 est requis."; exit 1; }

secret() {  # 32 octets aléatoires, en hexadécimal
  openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

if [ ! -f .env ]; then
  DOMAINE="${1:-localhost}"
  adresse_valide "$DOMAINE"
  PORT_HTTPS="${PORT_HTTPS:-8443}"
  if [ "$PORT_HTTPS" = "443" ]; then ADRESSE="https://$DOMAINE"; else ADRESSE="https://$DOMAINE:$PORT_HTTPS"; fi
  umask 077
  cat > .env <<EOF
# Généré par installer.sh le $(date '+%d/%m/%Y %H:%M'). Ne jamais publier ce fichier.
DOMAINE=$DOMAINE
PORT_HTTPS=$PORT_HTTPS
ADRESSE_PUBLIQUE=$ADRESSE
NOM_SERVEUR_MATRIX=messagerie.local
MOT_DE_PASSE_POSTGRES=$(secret)
MOT_DE_PASSE_ADMIN_KEYCLOAK=$(secret | cut -c1-24)
SECRET_ENREGISTREMENT_SYNAPSE=$(secret)
SECRET_MACAROON_SYNAPSE=$(secret)
SECRET_FORMULAIRE_SYNAPSE=$(secret)
SECRET_OIDC_SYNAPSE=$(secret)
SECRET_OIDC_CONSOLE=$(secret)
SECRET_SESSION_CONSOLE=$(secret)
EOF
  echo "Fichier .env créé avec des secrets aléatoires."
elif [ -n "${1:-}" ]; then
  echo "Une installation existe déjà (.env). Pour changer d'adresse : ./installer.sh --reinitialiser $1"
  exit 1
fi

if [ -n "$CHANGEMENT_ADRESSE" ]; then
  port=$(sed -n 's/^PORT_HTTPS=//p' .env)
  if [ "$port" = "443" ]; then nouvelle="https://$CHANGEMENT_ADRESSE"; else nouvelle="https://$CHANGEMENT_ADRESSE:$port"; fi
  sed -i.precedent -e "s#^DOMAINE=.*#DOMAINE=$CHANGEMENT_ADRESSE#" \
                   -e "s#^ADRESSE_PUBLIQUE=.*#ADRESSE_PUBLIQUE=$nouvelle#" .env
  rm -f .env.precedent
  echo "Nouvelle adresse : $nouvelle (comptes, conversations et certificat conservés)."
fi

set -a; . ./.env; set +a

echo "Construction et démarrage (la première fois : quelques minutes)…"
if ! docker compose up -d --build; then
  # Jour de la présentation, sans Internet : la reconstruction peut échouer. L'adresse n'est lue
  # qu'au démarrage des services : les images déjà construites suffisent.
  [ -n "$CHANGEMENT_ADRESSE" ] || exit 1
  echo "Reconstruction impossible (pas d'Internet ?) : redémarrage avec les images déjà construites…"
  docker compose up -d
fi

# --ssl-no-revoke : sous Windows, curl veut vérifier la révocation du certificat auprès d'un
# service extérieur ; notre autorité est interne (pas de liste de révocation publique).
# Les sorties sont jetées par des redirections du shell (« >/dev/null ») et non par « -o /dev/null » :
# avec MSYS_NO_PATHCONV=1, curl.exe sous Windows ne saurait pas écrire dans « /dev/null ».
echo -n "Attente du démarrage complet"
for _ in $(seq 1 120); do
  if docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./ca-messagerie.crt >/dev/null 2>&1 \
     && curl -fsS --ssl-no-revoke --cacert ca-messagerie.crt "$ADRESSE_PUBLIQUE/_matrix/client/versions" >/dev/null 2>&1 \
     && curl -fsS --ssl-no-revoke --cacert ca-messagerie.crt "$ADRESSE_PUBLIQUE/auth/realms/administration" >/dev/null 2>&1; then
    echo " : prêt."
    break
  fi
  echo -n "."; sleep 5
done

if [ -n "$CHANGEMENT_ADRESSE" ]; then
  # Keycloak a enregistré dans sa base, à la première installation, les adresses vers lesquelles
  # il a le droit de renvoyer un agent après sa connexion. On les remplace par la nouvelle :
  # l'ancienne est refusée (protection contre les redirections détournées).
  echo "Mise à jour des adresses autorisées dans Keycloak…"
  kcadm() {
    docker compose exec -T -e KC_CLI_PASSWORD="$MOT_DE_PASSE_ADMIN_KEYCLOAK" keycloak \
      /opt/keycloak/bin/kcadm.sh "$@" --config /tmp/kcadm.config
  }
  kcadm config credentials --server http://localhost:8080/auth --realm master --user admin >/dev/null 2>&1 \
    || { echo "Connexion à l'administration de Keycloak impossible (mot de passe dans .env ?)."; exit 1; }
  id_synapse=$(kcadm get clients -r administration -q clientId=synapse --fields id --format csv --noquotes | tr -d '\r')
  id_console=$(kcadm get clients -r administration -q clientId=console-securite --fields id --format csv --noquotes | tr -d '\r')
  kcadm update "clients/$id_synapse" -r administration \
    -s "redirectUris=[\"$ADRESSE_PUBLIQUE/_synapse/client/oidc/callback\"]" -s "webOrigins=[\"$ADRESSE_PUBLIQUE\"]"
  kcadm update "clients/$id_console" -r administration \
    -s "redirectUris=[\"$ADRESSE_PUBLIQUE/console/connexion/retour\"]" -s "webOrigins=[\"$ADRESSE_PUBLIQUE\"]" \
    -s "attributes.\"post.logout.redirect.uris\"=$ADRESSE_PUBLIQUE/console/"
  echo "Adresse changée. Sur chaque appareil, ouvrez la nouvelle adresse et reconnectez-vous."
fi

cat <<EOF

  Messagerie (navigateur)   : $ADRESSE_PUBLIQUE
  Téléphone                 : application Element (classique), serveur « $ADRESSE_PUBLIQUE »,
                              ou le navigateur du téléphone
  Console de sécurité       : $ADRESSE_PUBLIQUE/console
  Administration Keycloak   : http://127.0.0.1:8081/auth/admin  (cet ordinateur seulement)
                              identifiant « admin », mot de passe dans .env (MOT_DE_PASSE_ADMIN_KEYCLOAK)

  Comptes de démonstration (fictifs) : docs/comptes-demo.md
  Code TOTP d'un compte de démo     : python outils/code_totp.py awa.sawadogo  (ou python3)

  Certificat : le HTTPS utilise une autorité de certification INTERNE (aucun service extérieur).
  Pour que les navigateurs et téléphones lui fassent confiance, installez ca-messagerie.crt.
  Empreinte SHA-256 de l'autorité :
EOF
openssl x509 -in ca-messagerie.crt -noout -fingerprint -sha256 2>/dev/null | sed 's/^/    /' || true
