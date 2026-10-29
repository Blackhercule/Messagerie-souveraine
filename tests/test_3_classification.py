"""Classification des salons : CONFIDENTIEL réservé aux habilités, pas de déclassement,
expiration automatique des messages. Règles appliquées par le serveur (module de sécurité)."""

import time

import pytest

SEPT_JOURS = 7 * 86_400_000
TRENTE_JOURS = 30 * 86_400_000


def attendre_conservation(client, salon, delai=5.0):
    fin = time.time() + delai
    while time.time() < fin:
        etat = client.etat(salon, "m.room.retention")
        if etat:
            return etat.get("max_lifetime")
        time.sleep(0.2)
    return None


@pytest.fixture(scope="module")
def salon_confidentiel(console, awa, issouf):
    """Salon entre deux agents habilités, classé CONFIDENTIEL. (`console` synchronise les habilitations.)"""
    salon = awa.creer_salon("Préparation du conseil", invites=[issouf.identifiant])
    assert issouf.rejoindre(salon).status_code == 200
    r = awa.changer_etat(salon, "m.room.name", {"name": "[CONFIDENTIEL] Préparation du conseil"})
    assert r.status_code == 200, r.text
    return salon


def test_classification_impose_expiration_7_jours(awa, salon_confidentiel):
    assert attendre_conservation(awa, salon_confidentiel) == SEPT_JOURS


def test_invitation_non_habilite_refusee(awa, fatou, salon_confidentiel):
    r = awa.inviter(salon_confidentiel, fatou.identifiant)
    assert r.status_code == 403, r.text


def test_entree_non_habilite_refusee(fatou, salon_confidentiel):
    assert fatou.rejoindre(salon_confidentiel).status_code == 403


def test_declassement_refuse(awa, salon_confidentiel):
    r = awa.changer_etat(salon_confidentiel, "m.room.name", {"name": "Préparation du conseil"})
    assert r.status_code == 403
    r = awa.changer_etat(salon_confidentiel, "m.room.name", {"name": "[DIFFUSION RESTREINTE] Conseil"})
    assert r.status_code == 403


def test_allongement_conservation_refuse(awa, salon_confidentiel):
    r = awa.changer_etat(salon_confidentiel, "m.room.retention", {"max_lifetime": 365 * 86_400_000})
    assert r.status_code == 403
    r = awa.changer_etat(salon_confidentiel, "m.room.retention", {})
    assert r.status_code == 403


def test_raccourcir_conservation_autorise(awa, salon_confidentiel):
    r = awa.changer_etat(salon_confidentiel, "m.room.retention", {"max_lifetime": 86_400_000})
    assert r.status_code == 200


def test_classification_refusee_si_membre_non_habilite(console, awa, fatou):
    salon = awa.creer_salon("Projet de note", invites=[fatou.identifiant])
    r = awa.changer_etat(salon, "m.room.name", {"name": "[CONFIDENTIEL] Projet de note"})
    assert r.status_code == 403


def test_non_habilite_ne_peut_pas_creer_de_salon_confidentiel(console, fatou):
    r = fatou.appel("POST", "/createRoom", json={"name": "[CONFIDENTIEL] Mon salon"})
    assert r.status_code == 403


def test_diffusion_restreinte_expire_en_30_jours(awa, fatou):
    salon = awa.creer_salon("Coordination", invites=[fatou.identifiant])
    r = awa.changer_etat(salon, "m.room.name", {"name": "[DIFFUSION RESTREINTE] Coordination"})
    assert r.status_code == 200
    assert attendre_conservation(awa, salon) == TRENTE_JOURS
    # Un agent non habilité CONFIDENTIEL peut participer à un salon DIFFUSION RESTREINTE.
    assert fatou.rejoindre(salon).status_code == 200
