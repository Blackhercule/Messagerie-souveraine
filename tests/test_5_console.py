"""Console de sécurité : réservée aux administrateurs, protégée, et elle voit les intrusions."""

import re

import requests

from conftest import identifiants
from navigateur import ADRESSE, CA_RACINE, Navigateur, mxid


def test_console_exige_une_connexion():
    s = requests.Session()
    s.trust_env, s.verify = False, CA_RACINE
    r = s.get(f"{ADRESSE}/console/", allow_redirects=False)
    assert r.status_code == 302 and r.headers["Location"].endswith("/console/connexion")


def test_agent_sans_role_refuse():
    rep = Navigateur().connexion_console(*identifiants("fatou"))
    assert rep.status_code == 403 and "Accès refusé" in rep.text


def test_formulaire_sans_jeton_csrf_refuse(console):
    r = console.s.post(f"{ADRESSE}/console/agents/moussa.sanou/revoquer", data={"motif": "départ"})
    assert r.status_code == 400
    assert "moussa.sanou" in console.s.get(f"{ADRESSE}/console/agents").text  # toujours actif


def test_entetes_de_securite(console):
    r = console.s.get(f"{ADRESSE}/console/")
    assert "script-src 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Strict-Transport-Security" in r.headers


def test_journal_signale_les_intrusions(console):
    """Les tentatives ont été faites plus haut : test_1_acces (compte inconnu, visiteur non enrôlé)
    et test_agent_sans_role_refuse (agent sans rôle sur la console)."""
    page = console.s.get(f"{ADRESSE}/console/journal", params={"gravite": "intrus"}).text
    assert "Compte non enrôlé rejeté par la messagerie" in page
    assert "Identifiant inconnu" in page
    assert "Accès à la console refusé" in page
    # Après sa révocation (test_4), l'agent qui retente sa chance est signalé…
    assert "Agent révoqué : tentative de connexion refusée" in page
    # … mais ses connexions d'AVANT la révocation, légitimes, ne sont pas des intrusions.
    lignes = re.findall(r'<tr class="intrus">(.*?)</tr>', page, re.S)
    assert not [l for l in lignes if "Compte non enrôlé" in l and "test.revocation" in l]


def test_habilitation_donnee_puis_retiree(console, awa, fatou):
    salon = awa.creer_salon("Note au ministre")
    assert awa.changer_etat(salon, "m.room.name", {"name": "[CONFIDENTIEL] Note au ministre"}).status_code == 200
    assert awa.inviter(salon, fatou.identifiant).status_code == 403

    page = console.s.get(f"{ADRESSE}/console/agents").text
    console.poster_console("/console/agents/fatou.zongo/habilitation", page, {"habilite": "oui"})
    assert awa.inviter(salon, mxid("fatou.zongo")).status_code == 200

    page = console.s.get(f"{ADRESSE}/console/agents").text
    console.poster_console("/console/agents/fatou.zongo/habilitation", page, {"habilite": "non"})
    assert fatou.rejoindre(salon).status_code == 403  # l'invitation ne suffit plus


def test_administrateur_ne_peut_pas_se_revoquer_lui_meme(console):
    page = console.s.get(f"{ADRESSE}/console/agents").text
    rep = console.poster_console("/console/agents/admin.securite/revoquer", page, {"motif": "départ"})
    assert "ne peut pas révoquer son propre compte" in rep.text
    assert Navigateur().connexion_console(*identifiants("admin")).status_code == 200
