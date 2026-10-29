#!/usr/bin/env bash
# Installation de la messagerie souveraine en une commande.
#
#   ./installer.sh                     démonstration sur cet ordinateur (https://localhost:8443)
#   ./installer.sh 192.168.1.20        démonstration sur le réseau local (téléphones, autres PC)
#   ./installer.sh --reinitialiser …   efface TOUTES les données et recommence (changement d'adresse)
#
# Sous Windows : lancer ce script depuis « Git Bash », avec Docker Desktop démarré.
set -euo pipefail
# Git Bash (Windows) : ne pas transformer les chemins des conteneurs (« caddy:/data/… »).
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")"

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

set -a; . ./.env; set +a

echo "Construction et démarrage (la première fois : quelques minutes)…"
docker compose up -d --build

echo -n "Attente du démarrage complet"
for _ in $(seq 1 120); do
  if docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./ca-messagerie.crt >/dev/null 2>&1 \
     && curl -fsS --cacert ca-messagerie.crt "$ADRESSE_PUBLIQUE/_matrix/client/versions" >/dev/null 2>&1 \
     && curl -fsS --cacert ca-messagerie.crt -o /dev/null "$ADRESSE_PUBLIQUE/auth/realms/administration"; then
    echo " : prêt."
    break
  fi
  echo -n "."; sleep 5
done

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
