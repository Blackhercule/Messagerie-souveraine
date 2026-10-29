"""Client de l'API d'administration de Synapse (serveur de messagerie).

Cette API n'est accessible que depuis le réseau Docker privé : Caddy la bloque côté public.
"""

import hashlib
import hmac
import os
import secrets
from urllib.parse import quote

import requests

from .reglages import Reglages


class ErreurMessagerie(Exception):
    pass


class Messagerie:
    COMPTE_SERVICE = "console-securite"

    def __init__(self, reglages: Reglages):
        self.r = reglages
        self._fichier_jeton = os.path.join(reglages.dossier_donnees, "jeton-synapse")
        self._jeton = None

    # ------------------------------------------------------------------ compte de service
    def _entetes(self) -> dict:
        if self._jeton is None:
            self._jeton = self._charger_ou_creer_jeton()
        return {"Authorization": f"Bearer {self._jeton}"}

    def _charger_ou_creer_jeton(self) -> str:
        if os.path.exists(self._fichier_jeton):
            with open(self._fichier_jeton, encoding="utf-8") as f:
                jeton = f.read().strip()
            rep = requests.get(f"{self.r.synapse_interne}/_matrix/client/v3/account/whoami",
                               headers={"Authorization": f"Bearer {jeton}"}, timeout=10)
            if rep.status_code == 200:
                return jeton
        jeton = self._enregistrer_compte_service()
        os.makedirs(self.r.dossier_donnees, exist_ok=True)
        with open(self._fichier_jeton, "w", encoding="utf-8") as f:
            f.write(jeton)
        os.chmod(self._fichier_jeton, 0o600)
        return jeton

    def _enregistrer_compte_service(self) -> str:
        """Crée le compte administrateur technique de la console avec le secret partagé de Synapse.

        Le calcul HMAC-SHA1 ci-dessous est celui imposé par l'API officielle de Synapse
        (« shared-secret registration ») : ce n'est pas une cryptographie de l'équipe.
        """
        url = f"{self.r.synapse_interne}/_synapse/admin/v1/register"
        for essai in range(10):
            nom = self.COMPTE_SERVICE if essai == 0 else f"{self.COMPTE_SERVICE}-{essai}"
            nonce = requests.get(url, timeout=10).json()["nonce"]
            mot_de_passe = secrets.token_urlsafe(32)  # jamais utilisé : la connexion par mot de passe est fermée
            message = b"\x00".join([nonce.encode(), nom.encode(), mot_de_passe.encode(), b"admin"])
            mac = hmac.new(self.r.secret_enregistrement_synapse.encode(), message, hashlib.sha1).hexdigest()
            rep = requests.post(url, timeout=10, json={
                "nonce": nonce, "username": nom, "displayname": "Console de sécurité (service)",
                "password": mot_de_passe, "admin": True, "mac": mac,
            })
            if rep.status_code == 200:
                return rep.json()["access_token"]
            if rep.json().get("errcode") != "M_USER_IN_USE":
                raise ErreurMessagerie(f"Synapse refuse le compte de service : {rep.text[:200]}")
        raise ErreurMessagerie("Impossible de créer le compte de service de la console")

    def _appel(self, methode: str, chemin: str, **kwargs):
        rep = requests.request(methode, self.r.synapse_interne + chemin, headers=self._entetes(),
                               timeout=30, **kwargs)
        if rep.status_code == 404:
            return None
        if rep.status_code >= 400:
            raise ErreurMessagerie(f"Synapse : {methode} {chemin} → {rep.status_code} {rep.text[:200]}")
        return rep.json() if rep.content else None

    # ------------------------------------------------------------------ opérations
    def compte(self, identifiant: str):
        """None si l'agent ne s'est encore jamais connecté à la messagerie."""
        return self._appel("GET", f"/_synapse/admin/v2/users/{quote(identifiant)}")

    def appareils(self, identifiant: str) -> list:
        rep = self._appel("GET", f"/_synapse/admin/v2/users/{quote(identifiant)}/devices")
        return (rep or {}).get("devices", [])

    def deconnecter_appareils(self, identifiant: str) -> int:
        """Supprime tous les appareils : leurs jetons d'accès et leurs clés deviennent invalides."""
        ids = [a["device_id"] for a in self.appareils(identifiant)]
        if ids:
            self._appel("POST", f"/_synapse/admin/v2/users/{quote(identifiant)}/delete_devices",
                        json={"devices": ids})
        return len(ids)

    def desactiver(self, identifiant: str, effacer: bool = False) -> bool:
        """Désactive définitivement le compte : appareils supprimés, retiré de tous les salons."""
        if self.compte(identifiant) is None:
            return False
        self._appel("POST", f"/_synapse/admin/v1/deactivate/{quote(identifiant)}", json={"erase": effacer})
        return True

    def statistiques(self) -> dict:
        rep = self._appel("GET", "/_synapse/admin/v1/rooms", params={"limit": 1}) or {}
        return {"salons": rep.get("total_rooms", 0)}
