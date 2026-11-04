"""Client de l'API d'administration de Keycloak (identité des agents).

La console s'authentifie avec son propre compte de service (« client credentials »),
qui n'a que les droits nécessaires : gérer les utilisateurs et lire les événements.
"""

import json
import time

import requests

from .reglages import Reglages


class ErreurIdentite(Exception):
    pass


class Identite:
    def __init__(self, reglages: Reglages):
        self.r = reglages
        self._jeton = None
        self._expiration = 0.0
        self._base = f"{reglages.keycloak_interne}/admin/realms/{reglages.royaume}"

    # ------------------------------------------------------------------ outils HTTP
    def _entetes(self) -> dict:
        if not self._jeton or time.time() > self._expiration - 30:
            rep = requests.post(f"{self.r.oidc_interne}/token", timeout=10, data={
                "grant_type": "client_credentials",
                "client_id": self.r.client_id,
                "client_secret": self.r.client_secret,
            })
            if rep.status_code != 200:
                raise ErreurIdentite(f"Keycloak refuse le compte de service : {rep.status_code}")
            donnees = rep.json()
            self._jeton = donnees["access_token"]
            self._expiration = time.time() + donnees.get("expires_in", 60)
        return {"Authorization": f"Bearer {self._jeton}"}

    def _appel(self, methode: str, chemin: str, **kwargs):
        rep = requests.request(methode, self._base + chemin, headers=self._entetes(), timeout=10, **kwargs)
        if rep.status_code == 401:  # jeton refusé (Keycloak redémarré, clés changées) : on en redemande un
            self._jeton = None
            rep = requests.request(methode, self._base + chemin, headers=self._entetes(), timeout=10, **kwargs)
        if rep.status_code >= 400:
            raise ErreurIdentite(f"Keycloak : {methode} {chemin} → {rep.status_code} {rep.text[:200]}")
        return rep.json() if rep.content and "json" in rep.headers.get("Content-Type", "") else None

    # ------------------------------------------------------------------ utilisateurs
    def utilisateurs(self) -> list:
        return self._appel("GET", "/users", params={"max": 1000, "briefRepresentation": "false"}) or []

    def utilisateur(self, nom: str):
        trouves = self._appel("GET", "/users", params={"username": nom, "exact": "true",
                                                       "briefRepresentation": "false"}) or []
        return trouves[0] if trouves else None

    def exiger_utilisateur(self, nom: str) -> dict:
        u = self.utilisateur(nom)
        if u is None:
            raise ErreurIdentite(f"Agent inconnu : {nom}")
        return u

    @staticmethod
    def _second_facteur(secret_totp: str) -> dict:
        """Second facteur TOTP prêt à l'emploi (réglages du royaume : SHA-1, 6 chiffres, 30 s)."""
        return {
            "type": "otp",
            "userLabel": "Remis à l'enrôlement",
            "secretData": json.dumps({"value": secret_totp}),
            "credentialData": json.dumps({"subType": "totp", "digits": 6, "counter": 0, "period": 30,
                                          "algorithm": "HmacSHA1"}),
        }

    def creer(self, nom: str, prenom: str, nom_famille: str, attributs: dict, mot_de_passe_provisoire: str,
              groupes: list, secret_totp: str) -> None:
        self._appel("POST", "/users", json={
            "username": nom,
            "firstName": prenom,
            "lastName": nom_famille,
            "enabled": True,
            "attributes": attributs,
            "groups": [f"/{g}" for g in groupes],
            # Le second facteur est remis dès l'enrôlement (QR code) : à la première connexion,
            # le code est donc exigé, puis l'agent choisit son propre mot de passe.
            "requiredActions": ["UPDATE_PASSWORD"],
            "credentials": [{"type": "password", "value": mot_de_passe_provisoire, "temporary": True},
                            self._second_facteur(secret_totp)],
        })

    def modifier(self, utilisateur: dict, **champs) -> None:
        complet = self._appel("GET", f"/users/{utilisateur['id']}")
        complet.update(champs)
        self._appel("PUT", f"/users/{utilisateur['id']}", json=complet)

    def fermer_sessions(self, utilisateur: dict) -> None:
        """Ferme toutes les sessions ; Keycloak prévient aussi Synapse (déconnexion « back-channel »)."""
        self._appel("POST", f"/users/{utilisateur['id']}/logout")

    def supprimer_second_facteur(self, utilisateur: dict) -> int:
        identifiants = self._appel("GET", f"/users/{utilisateur['id']}/credentials") or []
        otp = [c for c in identifiants if c.get("type") == "otp"]
        for c in otp:
            self._appel("DELETE", f"/users/{utilisateur['id']}/credentials/{c['id']}")
        return len(otp)

    def remplacer_second_facteur(self, utilisateur: dict, secret_totp: str) -> int:
        """Supprime tout second facteur existant (téléphone perdu) et en installe un nouveau."""
        supprimes = self.supprimer_second_facteur(utilisateur)
        self.modifier(utilisateur, credentials=[self._second_facteur(secret_totp)], requiredActions=["UPDATE_PASSWORD"])
        if not self.a_un_second_facteur(utilisateur):
            raise ErreurIdentite("Keycloak n'a pas enregistré le nouveau second facteur")
        return supprimes

    def a_un_second_facteur(self, utilisateur: dict) -> bool:
        identifiants = self._appel("GET", f"/users/{utilisateur['id']}/credentials") or []
        return any(c.get("type") == "otp" for c in identifiants)

    def nouveau_mot_de_passe_provisoire(self, utilisateur: dict, mot_de_passe: str) -> None:
        self._appel("PUT", f"/users/{utilisateur['id']}/reset-password",
                    json={"type": "password", "value": mot_de_passe, "temporary": True})

    # ------------------------------------------------------------------ groupes
    def _id_groupe(self, nom: str) -> str:
        for g in self._appel("GET", "/groups", params={"search": nom, "exact": "true"}) or []:
            if g["name"] == nom:
                return g["id"]
        raise ErreurIdentite(f"Groupe introuvable dans Keycloak : {nom}")

    def groupes(self, utilisateur: dict) -> set:
        return {g["name"] for g in self._appel("GET", f"/users/{utilisateur['id']}/groups") or []}

    def membres(self, groupe: str) -> list:
        return self._appel("GET", f"/groups/{self._id_groupe(groupe)}/members",
                           params={"max": 1000, "briefRepresentation": "false"}) or []

    def ajouter_au_groupe(self, utilisateur: dict, groupe: str) -> None:
        self._appel("PUT", f"/users/{utilisateur['id']}/groups/{self._id_groupe(groupe)}")

    def retirer_du_groupe(self, utilisateur: dict, groupe: str) -> None:
        self._appel("DELETE", f"/users/{utilisateur['id']}/groups/{self._id_groupe(groupe)}")

    # ------------------------------------------------------------------ événements
    def evenements(self, types: list, maximum: int = 200) -> list:
        return self._appel("GET", "/events", params=[("type", t) for t in types] + [("max", maximum)]) or []
