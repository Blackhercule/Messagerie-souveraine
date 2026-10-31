"""Chiffrement : tout salon est chiffré, et le serveur refuse les messages en clair.

L'échange réellement chiffré de bout en bout (avec la bibliothèque officielle matrix-js-sdk
et son module de chiffrement Rust/vodozemac) est vérifié par tests/e2ee/echange.mjs, lancé
par test_echange_chiffre_illisible_en_base ci-dessous.
"""

import json
import os
import shlex
import shutil
import subprocess

import pytest

from conftest import connecter
from navigateur import ADRESSE, CA_RACINE

ALGORITHME_MEGOLM = "m.megolm.v1.aes-sha2"


@pytest.fixture(scope="module")
def salon_de_test(awa):
    return awa.creer_salon("Salon de test du chiffrement")


def test_salon_chiffre_des_sa_creation(awa):
    salon = awa.creer_salon("Équipe projet budget")
    chiffrement = awa.etat(salon, "m.room.encryption")
    assert chiffrement and chiffrement["algorithm"] == ALGORITHME_MEGOLM


def test_message_direct_chiffre(awa, issouf):
    salon = awa.ok("POST", "/createRoom", json={"is_direct": True, "preset": "trusted_private_chat",
                                                  "invite": [issouf.identifiant]})["room_id"]
    assert awa.etat(salon, "m.room.encryption")["algorithm"] == ALGORITHME_MEGOLM


@pytest.mark.parametrize("type_evenement,contenu", [
    ("m.room.message", {"msgtype": "m.text", "body": "Note confidentielle EN CLAIR"}),
    ("m.room.message", {"msgtype": "m.file", "body": "rapport.pdf", "url": "mxc://messagerie.local/x"}),
    ("m.sticker", {"body": "autocollant", "url": "mxc://messagerie.local/y", "info": {}}),
])
def test_message_en_clair_refuse_par_le_serveur(awa, salon_de_test, type_evenement, contenu):
    r = awa.envoyer(salon_de_test, type_evenement, contenu)
    assert r.status_code == 403, r.text
    assert r.json()["errcode"] == "M_FORBIDDEN"


@pytest.mark.parametrize("contenu", [{}, {"algorithm": "m.olm.v1.curve25519-aes-sha2"}, {"algorithm": "maison"}])
def test_retrait_ou_changement_du_chiffrement_refuse(awa, salon_de_test, contenu):
    r = awa.changer_etat(salon_de_test, "m.room.encryption", contenu)
    assert r.status_code == 403, r.text
    assert awa.etat(salon_de_test, "m.room.encryption")["algorithm"] == ALGORITHME_MEGOLM


def test_salon_sans_chiffrement_impossible_a_creer(awa):
    r = awa.appel("POST", "/createRoom", json={"name": "Sans chiffrement", "initial_state": [
        {"type": "m.room.encryption", "state_key": "", "content": {"algorithm": "aucun"}}]})
    assert r.status_code == 403, r.text


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js requis pour le test E2EE complet")
def test_echange_chiffre_illisible_en_base():
    """Deux agents échangent avec un vrai client Matrix ; la phrase ne doit apparaître nulle part en base."""
    dossier = os.path.join(os.path.dirname(__file__), "e2ee")
    if not os.path.isdir(os.path.join(dossier, "node_modules")):
        # Sous Windows, npm est un script « npm.cmd » : il faut son chemin complet.
        subprocess.run([shutil.which("npm") or "npm", "install", "--no-audit", "--no-fund"], cwd=dossier, check=True)
    # Deux nouveaux appareils, connectés par Keycloak (mot de passe + TOTP).
    sessions = {}
    for role, qui in (("expediteur", "awa"), ("destinataire", "issouf")):
        c = connecter(qui)
        sessions[role] = {"user_id": c.identifiant, "access_token": c.jeton, "device_id": c.appareil}
    env = {**os.environ, "ADRESSE_PUBLIQUE": ADRESSE, "NODE_EXTRA_CA_CERTS": os.path.abspath(CA_RACINE),
           "SESSIONS": json.dumps(sessions)}
    sortie = subprocess.run([shutil.which("node") or "node", "echange.mjs"], cwd=dossier, env=env, capture_output=True, text=True,
                            timeout=240)
    assert sortie.returncode == 0, sortie.stdout[-2000:] + sortie.stderr[-2000:]
    ligne = next(l for l in sortie.stdout.splitlines() if l.startswith("RESULTAT "))
    resultat = json.loads(ligne.removeprefix("RESULTAT "))
    assert resultat["dechiffre_par_destinataire"] == resultat["phrase"]
    assert resultat["type_sur_le_serveur"] == "m.room.encrypted"
    assert resultat["algorithme"] == ALGORITHME_MEGOLM

    # Ce que voit le serveur : on cherche la phrase dans TOUTE la base de Synapse.
    psql = shlex.split(os.environ.get("COMMANDE_PSQL",
                                     "docker compose exec -T postgres psql -U synapse -d synapse -At"))
    secret = resultat["phrase"].split(" : ")[0]  # « Note confidentielle n°… », unique à cette exécution

    def sql(requete):
        return subprocess.run(psql + ["-c", requete], capture_output=True, text=True, check=True).stdout.strip()

    tables = sql("SELECT table_name FROM information_schema.columns WHERE table_schema = 'public' "
                 "AND data_type IN ('text', 'character varying', 'bytea', 'json', 'jsonb') "
                 "GROUP BY table_name").split()
    for table in tables:
        assert sql(f"SELECT count(*) FROM {table} t WHERE t::text LIKE '%{secret}%'") == "0", \
            f"le texte du message apparaît en clair dans la table {table} !"
    stocke = json.loads(sql(f"SELECT json FROM event_json WHERE event_id = '{resultat['event_id']}'"))
    assert stocke["type"] == "m.room.encrypted"
    assert stocke["content"]["algorithm"] == ALGORITHME_MEGOLM
    assert "ciphertext" in stocke["content"] and "body" not in stocke["content"]
