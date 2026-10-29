"""Réglages de la console, lus dans les variables d'environnement (fichier .env)."""

import os


def _exiger(nom: str) -> str:
    valeur = os.environ.get(nom)
    if not valeur:
        raise RuntimeError(f"Variable d'environnement manquante : {nom}")
    return valeur


class Reglages:
    def __init__(self):
        self.adresse_publique = _exiger("ADRESSE_PUBLIQUE").rstrip("/")
        self.nom_serveur = _exiger("NOM_SERVEUR_MATRIX")
        self.royaume = os.environ.get("ROYAUME_KEYCLOAK", "administration")
        # Adresses internes (réseau Docker privé) : jamais exposées au public.
        self.keycloak_interne = os.environ.get("KEYCLOAK_INTERNE", "http://keycloak:8080/auth").rstrip("/")
        self.synapse_interne = os.environ.get("SYNAPSE_INTERNE", "http://synapse:8008").rstrip("/")
        self.client_id = os.environ.get("CLIENT_OIDC_CONSOLE", "console-securite")
        self.client_secret = _exiger("SECRET_OIDC_CONSOLE")
        self.secret_enregistrement_synapse = _exiger("SECRET_ENREGISTREMENT_SYNAPSE")
        self.secret_session = _exiger("SECRET_SESSION_CONSOLE")
        self.dossier_journal = os.environ.get("DOSSIER_JOURNAL", "/journal")
        self.dossier_donnees = os.environ.get("DOSSIER_DONNEES", "/donnees")
        self.role_admin = "administrateur-securite"
        self.groupe_agents = "agents"
        self.groupe_habilites = "habilites-confidentiel"

    @property
    def emetteur_oidc(self) -> str:
        return f"{self.adresse_publique}/auth/realms/{self.royaume}"

    @property
    def oidc_interne(self) -> str:
        return f"{self.keycloak_interne}/realms/{self.royaume}/protocol/openid-connect"

    def identifiant_matrix(self, nom_utilisateur: str) -> str:
        return f"@{nom_utilisateur}:{self.nom_serveur}"
