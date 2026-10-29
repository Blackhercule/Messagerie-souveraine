"""Accès : seuls les agents enrôlés, avec un second facteur, peuvent entrer."""

import pytest
import requests

from conftest import identifiants
from navigateur import ADRESSE, CA_RACINE, EchecConnexion, Navigateur


def public():
    s = requests.Session()
    s.trust_env, s.verify = False, CA_RACINE
    return s


def test_seule_la_connexion_sso_est_proposee():
    flux = public().get(f"{ADRESSE}/_matrix/client/v3/login").json()["flows"]
    types = {f["type"] for f in flux}
    assert "m.login.sso" in types
    assert "m.login.password" not in types, "la connexion par simple mot de passe doit être fermée"


def test_inscription_libre_impossible():
    r = public().post(f"{ADRESSE}/_matrix/client/v3/register",
                      json={"username": "pirate", "password": "Pirate-2026-Pirate", "auth": {"type": "m.login.dummy"}})
    assert r.status_code == 403


def test_mot_de_passe_matrix_refuse():
    r = public().post(f"{ADRESSE}/_matrix/client/v3/login", json={
        "type": "m.login.password", "identifier": {"type": "m.id.user", "user": "awa.sawadogo"},
        "password": "Demo-Awa-2026"})
    assert r.status_code in (400, 403)


@pytest.mark.parametrize("chemin", ["/_synapse/admin/v1/server_version", "/_synapse/admin/v2/users",
                                    "/auth/admin/master/console/", "/auth/admin/realms/administration/users"])
def test_api_administration_non_exposees(chemin):
    assert public().get(ADRESSE + chemin).status_code == 404


def test_federation_desactivee():
    assert public().get(f"{ADRESSE}/_matrix/federation/v1/version").status_code == 404
    assert public().get(f"{ADRESSE}/_matrix/key/v2/server").status_code == 404


def test_second_facteur_exige():
    """Le bon mot de passe ne suffit pas : la page du code TOTP s'affiche et rien n'est délivré."""
    nom, mot_de_passe, _ = identifiants("moussa")
    n = Navigateur()
    with pytest.raises(EchecConnexion) as e:
        n.connexion_matrix(nom, mot_de_passe, code_force="000000")
    assert e.value.etape == "code TOTP refusé"


def test_compte_inconnu_refuse():
    with pytest.raises(EchecConnexion) as e:
        Navigateur().connexion_matrix("inconnu.total", "N-importe-quoi-2026")
    assert e.value.etape == "identifiants refusés"


def test_identite_non_enrolee_refusee_par_la_messagerie():
    """« visiteur.externe » a un compte valide (mot de passe + TOTP) mais n'est pas dans le groupe agents."""
    with pytest.raises(EchecConnexion) as e:
        Navigateur().connexion_matrix(*identifiants("visiteur"))
    assert e.value.etape.startswith("messagerie refusée")


def test_agent_enrole_avec_second_facteur(awa):
    assert awa.identifiant.startswith("@awa.sawadogo:")
    assert awa.ok("GET", "/account/whoami")["user_id"] == awa.identifiant
