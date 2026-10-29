"""Journal de sécurité : actions de la console, refus du serveur et événements de connexion."""

import json
import os
import threading
from datetime import datetime, timezone

_verrou = threading.Lock()

# Erreurs de connexion de Keycloak, traduites pour l'administrateur.
ERREURS_CONNEXION = {
    "user_not_found": ("intrus", "Identifiant inconnu : compte non enrôlé"),
    "invalid_user_credentials": ("alerte", "Mot de passe ou code du second facteur incorrect"),
    "user_disabled": ("intrus", "Agent révoqué : tentative de connexion refusée"),
    "user_temporarily_disabled": ("alerte", "Compte bloqué temporairement (trop d'essais)"),
    "invalid_totp": ("alerte", "Code du second facteur incorrect"),
}

TYPES_SERVEUR = {
    "message_en_clair_refuse": ("alerte", "Message non chiffré refusé par le serveur"),
    "chiffrement_modifie_refuse": ("alerte", "Tentative de retirer le chiffrement d'un salon refusée"),
    "acces_confidentiel_refuse": ("intrus", "Accès à un salon CONFIDENTIEL refusé (non habilité)"),
    "declassement_refuse": ("alerte", "Déclassement d'un salon refusé"),
    "classification_refusee": ("alerte", "Classification CONFIDENTIEL refusée (membres non habilités)"),
    "conservation_refusee": ("alerte", "Allongement de la conservation refusé"),
    "classification_appliquee": ("info", "Salon classifié : expiration automatique appliquée"),
}


def maintenant() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Journal:
    def __init__(self, dossier: str):
        self.dossier = dossier
        self.fichier_console = os.path.join(dossier, "evenements-console.jsonl")
        self.fichier_serveur = os.path.join(dossier, "evenements-serveur.jsonl")

    def noter(self, type_evenement: str, gravite: str, auteur: str, cible: str, detail: str) -> None:
        ligne = {"date": maintenant(), "source": "console", "type": type_evenement, "gravite": gravite,
                 "auteur": auteur, "cible": cible, "detail": detail}
        os.makedirs(self.dossier, exist_ok=True)
        with _verrou, open(self.fichier_console, "a", encoding="utf-8") as f:
            f.write(json.dumps(ligne, ensure_ascii=False) + "\n")

    @staticmethod
    def _lire(fichier: str) -> list:
        try:
            with open(fichier, encoding="utf-8") as f:
                return [json.loads(l) for l in f if l.strip()]
        except (OSError, ValueError):
            return []

    def tout(self, evenements_keycloak: list, agents: set) -> list:
        """Fusionne les trois sources, du plus récent au plus ancien."""
        lignes = []
        for e in self._lire(self.fichier_console):
            lignes.append({**e, "libelle": e["detail"]})
        for e in self._lire(self.fichier_serveur):
            gravite, libelle = TYPES_SERVEUR.get(e["type"], ("info", e["type"]))
            lignes.append({"date": e["date"], "source": "serveur", "type": e["type"], "gravite": gravite,
                           "auteur": e.get("utilisateur", ""), "cible": e.get("salon", ""),
                           "libelle": libelle, "detail": e.get("detail", "")})
        for e in evenements_keycloak:
            date = datetime.fromtimestamp(e.get("time", 0) / 1000, timezone.utc).isoformat(timespec="seconds")
            nom = (e.get("details") or {}).get("username", "")
            if e.get("type") == "LOGIN_ERROR":
                gravite, libelle = ERREURS_CONNEXION.get(e.get("error", ""), ("alerte", "Connexion refusée"))
                lignes.append({"date": date, "source": "identite", "type": "connexion_refusee", "gravite": gravite,
                               "auteur": nom, "cible": e.get("ipAddress", ""), "libelle": libelle,
                               "detail": e.get("error", "")})
            elif e.get("type") == "LOGIN" and e.get("clientId") == "synapse" and nom and nom not in agents:
                # Identité valide, mais compte hors du groupe « agents » : Synapse le rejette.
                lignes.append({"date": date, "source": "identite", "type": "non_enrole_rejete", "gravite": "intrus",
                               "auteur": nom, "cible": e.get("ipAddress", ""),
                               "libelle": "Compte non enrôlé rejeté par la messagerie", "detail": ""})
        lignes.sort(key=lambda l: l["date"], reverse=True)
        return lignes
