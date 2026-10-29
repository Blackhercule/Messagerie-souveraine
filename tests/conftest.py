"""Comptes de démonstration (fictifs) et fixtures partagées par les tests de sécurité."""

import pytest

from navigateur import Navigateur, cle_totp_depuis_secret

# Comptes FICTIFS créés par keycloak/realm-administration.json (voir docs/comptes-demo.md).
COMPTES = {
    "admin": ("admin.securite", "Demo-Admin-2026", "DemoAdminSecu2026!!"),
    "awa": ("awa.sawadogo", "Demo-Awa-2026", "DemoAwaSawadogo2026"),          # habilitée CONFIDENTIEL
    "issouf": ("issouf.ouedraogo", "Demo-Issouf-2026", "DemoIssoufOuedrao26"),  # habilité CONFIDENTIEL
    "fatou": ("fatou.zongo", "Demo-Fatou-2026", "DemoFatouZongo2026!"),        # agent sans habilitation
    "moussa": ("moussa.sanou", "Demo-Moussa-2026", "DemoMoussaSanou2026"),
    "visiteur": ("visiteur.externe", "Demo-Visiteur-2026", "DemoVisiteurExt2026"),  # identité NON enrôlée
}


def identifiants(qui: str):
    nom, mot_de_passe, secret = COMPTES[qui]
    return nom, mot_de_passe, cle_totp_depuis_secret(secret)


def connecter(qui: str):
    return Navigateur().connexion_matrix(*identifiants(qui))


@pytest.fixture(scope="session")
def awa():
    return connecter("awa")


@pytest.fixture(scope="session")
def issouf():
    return connecter("issouf")


@pytest.fixture(scope="session")
def fatou():
    return connecter("fatou")


@pytest.fixture(scope="session")
def console():
    """Navigateur connecté à la console de sécurité en tant qu'administrateur."""
    n = Navigateur()
    rep = n.connexion_console(*identifiants("admin"))
    assert rep.status_code == 200 and "Tableau de bord" in rep.text, rep.text[:500]
    return n
