# Messagerie souveraine de l'administration

Prototype de messagerie instantanée pour les agents de l'État : **chiffrée de bout en bout**,
**hébergée sur nos propres machines**, **réservée aux agents enrôlés**, avec une **console de
sécurité** qui coupe l'accès d'un agent sur tous ses appareils en quelques secondes au plus.

> Toutes les données et tous les comptes de ce dépôt sont **fictifs**.

## Ce que fait le prototype

| Exigence | Réponse |
|---|---|
| Chiffrement de bout en bout | Protocole **Matrix (Olm/Megolm)**, éprouvé et audité. **Aucune cryptographie écrite par l'équipe.** |
| Aucun message en clair sur le serveur | Le serveur **refuse** tout message non chiffré et tout retrait du chiffrement (module `synapse/securite_messagerie`). Vérifié par un test qui cherche le texte dans toute la base. |
| Hébergement souverain | Tout tourne sur la machine de l'administration (`docker compose`). Réseau interne **sans accès à Internet**, pas de fédération, HTTPS par une autorité de certification **interne**. |
| Agents enrôlés + second facteur | Connexion uniquement par **Keycloak** : mot de passe + **code TOTP** obligatoire. Pas d'inscription libre. Un compte hors du groupe « agents » est rejeté. |
| Rôles | `administrateur-securite` (console), groupe `habilites-confidentiel` (salons CONFIDENTIEL). |
| Révocation immédiate | Console → « Révoquer » : compte désactivé, sessions fermées, **tous les appareils déconnectés**, retiré des conversations. |
| Métadonnées minimisées | Pas de présence, IP gardées 1 jour, notifications sans contenu, expiration automatique des salons classifiés. Détail : [note de sécurité](docs/note-securite.md). |

**Notre apport (cybersécurité)** : classification des salons `[DIFFUSION RESTREINTE]` /
`[CONFIDENTIEL]` imposée par le serveur (accès réservé aux habilités, déclassement interdit,
messages effacés après 30 / 7 jours), bouton d'urgence « téléphone perdu », journal de sécurité
qui signale les intrusions, et **41 tests de sécurité automatisés**.

## Architecture

```
  Navigateur : Element Web            Téléphone : application Element
             \                           /
              \      HTTPS (port 8443)  /
               +-------- Caddy --------+      seul point d'entrée ; API d'administration bloquées
               |          |            |
           Synapse     Keycloak    Console de sécurité
        (+ module de   (identité,   (enrôlement, révocation,
         sécurité)     TOTP, rôles)  urgence, journal)
               \          |            /
                 ----- PostgreSQL -----        réseau Docker interne, sans accès à Internet
```

## Installation (une commande)

Prérequis : Docker et Docker Compose (sous Windows : Docker Desktop, puis **Git Bash**).

```bash
./installer.sh                 # démonstration sur cet ordinateur : https://localhost:8443
./installer.sh 192.168.1.20    # ou sur le réseau local, pour les téléphones (adresse IP du PC)
./installer.sh --changer-adresse 10.0.0.5   # autre réseau : comptes, messages et certificat conservés
```

Le script crée `.env` avec des secrets aléatoires, construit et démarre tous les services,
puis affiche les adresses. Il exporte aussi `ca-messagerie.crt`, l'autorité de certification
interne, à installer sur les navigateurs et téléphones de démonstration.

- Messagerie : `https://localhost:8443` ; sur téléphone, l'application **Element (classique)** avec
  cette adresse de serveur, ou simplement le navigateur du téléphone
- Console de sécurité : `https://localhost:8443/console` (compte `admin.securite`)
- Comptes fictifs, codes TOTP et scénario de démonstration : [docs/comptes-demo.md](docs/comptes-demo.md)

## Tests de sécurité automatisés

```bash
pip install -r tests/requirements.txt
cd tests && python -m pytest -v        # Node.js est requis pour le test de chiffrement réel
```

Ils vérifient notamment : connexion impossible sans second facteur, compte inconnu ou non
enrôlé rejeté, inscription libre fermée, API d'administration et fédération inaccessibles,
message en clair refusé, **échange chiffré réel** (bibliothèque officielle `matrix-js-sdk`)
dont le texte n'apparaît **dans aucune table** de la base, classification, révocation sur deux
appareils pendant une conversation de groupe, bouton d'urgence, protections de la console.

## Technologies et licences

| Composant | Rôle | Licence |
|---|---|---|
| Synapse 1.164.1 | Serveur Matrix | AGPL-3.0 |
| Element Web 1.12.33, Element Android / iOS | Applications web et mobile | AGPL-3.0 |
| vodozemac (dans Element et matrix-js-sdk) | Olm / Megolm (Curve25519, Ed25519, AES-256, HMAC-SHA-256) | Apache-2.0 |
| Keycloak 26.8.1 | Identité, TOTP, rôles | Apache-2.0 |
| PostgreSQL 16 | Base de données | PostgreSQL License |
| Caddy 2.11.2 | HTTPS, autorité de certification interne | Apache-2.0 |
| Flask, Authlib / Requests / Gunicorn | Console de sécurité | BSD-3-Clause / Apache-2.0 / MIT |
| pytest, pyotp, matrix-js-sdk | Tests | MIT / MIT / Apache-2.0 |
| Docker Engine et Compose | Déploiement | Apache-2.0 |

**Niveau d'engagement open source : « Étendre et adapter ».** Nous ne modifions pas le code de
Synapse, d'Element ni de Keycloak (seul ajout : un script de quelques lignes, chargé avant
Element Web, pour l'utiliser dans le navigateur des téléphones — `caddy/sans-guide-mobile.js`) :
nous les configurons pour la souveraineté, nous **étendons**
Synapse par son API officielle de modules et nous ajoutons une console qui pilote Keycloak et
Synapse par leurs API d'administration.

Notre code (module serveur, console, configuration, déploiement, tests) est publié sous
**AGPL-3.0** ([LICENSE](LICENSE)), licence compatible avec Synapse et Element.

## Organisation du dépôt

`synapse/` serveur et module de sécurité · `keycloak/` royaume (rôles, groupes, comptes fictifs) ·
`console/` console de sécurité · `caddy/` HTTPS et Element · `element/` configuration d'Element ·
`postgres/` bases · `tests/` tests de sécurité · `outils/` aides à la démonstration · `docs/` notes.

## Limites connues

- Les **noms des salons** et la liste des membres ne sont pas chiffrés (fonctionnement de Matrix) :
  ne pas mettre d'information sensible dans un nom de salon.
- Sans service de notification (Google/Apple), l'application Android se synchronise en
  arrière-plan ; sur iPhone, les notifications instantanées nécessitent le service d'Apple.
- Une capture d'écran ou un transfert par l'agent lui-même ne peut pas être empêché.
- Prototype : une seule machine, pas de sauvegarde automatique ni de haute disponibilité.

Détails et menaces traitées : [note de sécurité](docs/note-securite.md) ·
projet : [note de pré-projet](docs/note-pre-projet.md).
