"""Révocation : un agent qui quitte l'administration perd l'accès partout, immédiatement.

Le scénario suit la démonstration demandée par le jury : un agent est enrôlé, se connecte
sur deux appareils, participe à une conversation de groupe, puis est révoqué depuis la console.
"""

import re
import time

import pytest

from navigateur import ADRESSE, EchecConnexion, Navigateur


def secrets_remis(page: str) -> tuple:
    """Mot de passe provisoire et clé du second facteur affichés par la console (une seule fois)."""
    provisoire = re.search(r'<code class="secret">([^<]+)</code>', page).group(1)
    cle = re.search(r'<code class="secret cle-totp">([^<]+)</code>', page).group(1).replace(" ", "")
    assert "<svg" in page, "le QR code du second facteur doit être affiché"
    return provisoire, cle


def enroler(console, prenom: str, nom: str) -> tuple:
    page = console.s.get(f"{ADRESSE}/console/agents/nouveau").text
    rep = console.poster_console("/console/agents/nouveau", page, {
        "prenom": prenom, "nom": nom, "ministere": "Ministère fictif des Tests", "fonction": "Agent de test"})
    assert rep.status_code == 200, rep.text[:500]
    identifiant = re.search(r"<dt>Identifiant</dt><dd><code>([^<]+)</code>", rep.text).group(1)
    provisoire, cle = secrets_remis(rep.text)
    return identifiant, provisoire, cle


def agent_avec_deux_appareils(console, nom_famille: str):
    """Enrôle un agent, fait sa première connexion (code TOTP + nouveau mot de passe), puis un 2ᵉ appareil."""
    identifiant, provisoire, cle = enroler(console, "Test", nom_famille)
    premier = Navigateur()
    telephone = premier.connexion_matrix(identifiant, provisoire, cle)  # première connexion guidée
    assert premier.nouveau_mot_de_passe
    ordinateur = Navigateur().connexion_matrix(identifiant, premier.nouveau_mot_de_passe, cle)
    assert telephone.appareil != ordinateur.appareil
    return identifiant, premier.nouveau_mot_de_passe, cle, telephone, ordinateur


def jeton_valide(client) -> bool:
    r = client.appel("GET", "/account/whoami")
    if r.status_code == 401:
        assert r.json()["errcode"] == "M_UNKNOWN_TOKEN"
        return False
    return r.status_code == 200


def test_premiere_connexion_impose_mot_de_passe_et_second_facteur(console):
    identifiant, provisoire, cle = enroler(console, "Test", f"Enrolement{int(time.time())}")
    # Dès la première connexion, le mot de passe provisoire ne suffit pas : le code est exigé.
    with pytest.raises(EchecConnexion) as e:
        Navigateur().connexion_matrix(identifiant, provisoire, code_force="000000")
    assert e.value.etape == "code TOTP refusé"
    # Avec le second facteur remis à l'enrôlement, Keycloak impose ensuite un nouveau mot de passe.
    n = Navigateur()
    n.connexion_matrix(identifiant, provisoire, cle)
    assert n.nouveau_mot_de_passe, "Keycloak doit imposer un nouveau mot de passe"
    # Le mot de passe provisoire ne fonctionne plus.
    with pytest.raises(EchecConnexion):
        Navigateur().connexion_matrix(identifiant, provisoire, cle)


def test_revocation_immediate_sur_tous_les_appareils(console, awa):
    identifiant, mot_de_passe, cle, telephone, ordinateur = agent_avec_deux_appareils(
        console, f"Revocation{int(time.time())}")

    # Conversation de groupe avec Awa.
    salon = awa.creer_salon("Cellule de crise (test)", invites=[telephone.identifiant])
    assert telephone.rejoindre(salon).status_code == 200
    assert awa.membres(salon)[telephone.identifiant] == "join"
    assert jeton_valide(telephone) and jeton_valide(ordinateur)

    # Révocation depuis la console.
    page = console.s.get(f"{ADRESSE}/console/agents").text
    debut = time.monotonic()
    rep = console.poster_console(f"/console/agents/{identifiant}/revoquer", page, {"motif": "départ"})
    assert rep.status_code == 200 and "est révoqué : 2 appareil(s) déconnecté(s)" in rep.text, rep.text[:800]

    # Immédiatement : plus aucun appareil ne fonctionne…
    assert not jeton_valide(telephone)
    assert not jeton_valide(ordinateur)
    duree = time.monotonic() - debut
    assert duree < 5, f"révocation trop lente : {duree:.1f} s"
    # … l'agent a quitté la conversation de groupe …
    assert awa.membres(salon)[telephone.identifiant] == "leave"
    # … et il ne peut plus se reconnecter, même avec son mot de passe et son second facteur.
    with pytest.raises(EchecConnexion):
        Navigateur().connexion_matrix(identifiant, mot_de_passe, cle)


def test_bouton_urgence_telephone_perdu(console):
    identifiant, mot_de_passe, cle, telephone, ordinateur = agent_avec_deux_appareils(
        console, f"Urgence{int(time.time())}")

    page = console.s.get(f"{ADRESSE}/console/agents").text
    rep = console.poster_console(f"/console/agents/{identifiant}/urgence", page, {})
    assert rep.status_code == 200 and "Appareils coupés" in rep.text
    assert "2 appareil(s) déconnecté(s)" in rep.text
    nouveau_provisoire, nouvelle_cle = secrets_remis(rep.text)
    assert nouvelle_cle != cle

    assert not jeton_valide(telephone) and not jeton_valide(ordinateur)
    # L'ancien mot de passe et l'ancien second facteur (peut-être sur le téléphone volé) ne servent plus.
    with pytest.raises(EchecConnexion):
        Navigateur().connexion_matrix(identifiant, mot_de_passe, cle)
    # L'agent se réenrôle avec le mot de passe provisoire et le nouveau QR code remis en main propre.
    n = Navigateur()
    nouveau_telephone = n.connexion_matrix(identifiant, nouveau_provisoire, nouvelle_cle)
    assert n.nouveau_mot_de_passe
    assert nouveau_telephone.identifiant == telephone.identifiant
