"""Opérations de sécurité : enrôlement, révocation, urgence (téléphone perdu), habilitations.

Chaque opération agit sur les DEUX systèmes : l'identité (Keycloak) et la messagerie (Synapse),
puis est notée dans le journal de sécurité.
"""

import json
import os
import re
import secrets
import time
import unicodedata

from .identite import Identite
from .journal import Journal
from .messagerie import Messagerie
from .reglages import Reglages
from .second_facteur import cle_base32, nouveau_secret


class ErreurOperation(Exception):
    pass


def nom_utilisateur(prenom: str, nom: str) -> str:
    """« Aïcha », « Ouédraogo » → « aicha.ouedraogo »."""
    def simplifier(texte: str) -> str:
        sans_accents = unicodedata.normalize("NFKD", texte).encode("ascii", "ignore").decode()
        return re.sub(r"[^a-z0-9]+", "-", sans_accents.lower()).strip("-")
    p, n = simplifier(prenom), simplifier(nom)
    if not p or not n:
        raise ErreurOperation("Prénom et nom obligatoires.")
    return f"{p}.{n}"


def mot_de_passe_provisoire() -> str:
    """Mot de passe à usage unique, à changer à la première connexion."""
    return "Provisoire-" + secrets.token_urlsafe(9)


class Operations:
    def __init__(self, reglages: Reglages):
        self.r = reglages
        self.identite = Identite(reglages)
        self.messagerie = Messagerie(reglages)
        self.journal = Journal(reglages.dossier_journal)
        self.fichier_habilitations = os.path.join(reglages.dossier_journal, "habilitations.json")

    # ------------------------------------------------------------------ lecture
    def agents(self) -> list:
        """Tous les comptes de l'annuaire, avec leur état dans la messagerie."""
        resultat = []
        for u in self.identite.utilisateurs():
            if u.get("serviceAccountClientId") or u["username"].startswith("service-account-"):
                continue
            groupes = self.identite.groupes(u)
            attributs = u.get("attributes") or {}
            resultat.append({
                "nom": u["username"],
                "prenom": u.get("firstName", ""),
                "nom_famille": u.get("lastName", ""),
                "ministere": (attributs.get("ministere") or [""])[0],
                "fonction": (attributs.get("fonction") or [""])[0],
                "actif": u.get("enabled", False),
                "enrole": self.r.groupe_agents in groupes,
                "habilite": self.r.groupe_habilites in groupes,
                "second_facteur": "CONFIGURE_TOTP" not in (u.get("requiredActions") or []),
            })
        return sorted(resultat, key=lambda a: (not a["actif"], a["nom_famille"], a["prenom"]))

    def noms_non_enroles(self) -> set:
        """Comptes actifs dans l'annuaire mais absents du groupe « agents » (ex. visiteur.externe).

        Un agent révoqué est désactivé : il n'est pas dans cette liste, ses anciennes
        connexions (légitimes à l'époque) ne sont donc pas signalées comme intrusions."""
        agents = {u["username"] for u in self.identite.membres(self.r.groupe_agents)}
        return {u["username"] for u in self.identite.utilisateurs()
                if u.get("enabled") and u["username"] not in agents
                and not u["username"].startswith("service-account-")}

    def journal_complet(self) -> list:
        evenements = self.identite.evenements(["LOGIN", "LOGIN_ERROR"])
        return self.journal.tout(evenements, self.noms_non_enroles())

    # ------------------------------------------------------------------ enrôlement
    def enroler(self, auteur: str, prenom: str, nom: str, ministere: str, fonction: str,
                habilite: bool) -> tuple:
        """Crée le compte avec un mot de passe provisoire ET son second facteur.

        Renvoie (identifiant, mot de passe provisoire, clé TOTP) : les deux secrets ne sont affichés
        qu'une fois, pour être remis à l'agent en main propre, et ne sont conservés nulle part ici."""
        identifiant = nom_utilisateur(prenom, nom)
        if self.identite.utilisateur(identifiant) is not None:
            raise ErreurOperation(f"Un compte « {identifiant} » existe déjà.")
        provisoire = mot_de_passe_provisoire()
        secret = nouveau_secret()
        groupes = [self.r.groupe_agents] + ([self.r.groupe_habilites] if habilite else [])
        self.identite.creer(identifiant, prenom.strip(), nom.strip(),
                            {"ministere": [ministere.strip()], "fonction": [fonction.strip()]},
                            provisoire, groupes, secret)
        self.synchroniser_habilitations()
        self.journal.noter("enrolement", "info", auteur, identifiant,
                           f"Agent enrôlé ({ministere.strip()}), second facteur remis"
                           + (" – habilité CONFIDENTIEL" if habilite else ""))
        return identifiant, provisoire, cle_base32(secret)

    # ------------------------------------------------------------------ révocation
    def revoquer(self, auteur: str, identifiant: str, motif: str) -> dict:
        """Départ de l'agent : accès coupé partout, immédiatement et définitivement."""
        if identifiant == auteur:
            raise ErreurOperation("Un administrateur ne peut pas révoquer son propre compte.")
        debut = time.monotonic()
        u = self.identite.exiger_utilisateur(identifiant)
        mxid = self.r.identifiant_matrix(identifiant)
        appareils = len(self.messagerie.appareils(mxid))  # compté avant la coupure
        # 1. Identité : compte désactivé, sessions fermées, retiré des groupes.
        self.identite.modifier(u, enabled=False)
        self.identite.fermer_sessions(u)
        for groupe in (self.r.groupe_agents, self.r.groupe_habilites):
            if groupe in self.identite.groupes(u):
                self.identite.retirer_du_groupe(u, groupe)
        self.synchroniser_habilitations()
        # 2. Messagerie : tous les appareils déconnectés, retiré de tous les salons.
        desactive = self.messagerie.desactiver(mxid)
        duree = int((time.monotonic() - debut) * 1000)
        self.journal.noter("revocation", "critique", auteur, identifiant,
                           f"Révocation ({motif}) : {appareils} appareil(s) déconnecté(s), "
                           f"compte de messagerie {'désactivé' if desactive else 'jamais utilisé'}, en {duree} ms")
        return {"appareils": appareils, "duree_ms": duree}

    def urgence(self, auteur: str, identifiant: str) -> tuple:
        """Téléphone perdu ou volé : tout est coupé, l'agent se réenrôle sur un nouvel appareil."""
        if identifiant == auteur:
            raise ErreurOperation("Demandez à un autre administrateur de couper vos appareils.")
        u = self.identite.exiger_utilisateur(identifiant)
        mxid = self.r.identifiant_matrix(identifiant)
        appareils = len(self.messagerie.appareils(mxid))  # compté avant la coupure
        # Fermer les sessions Keycloak déconnecte déjà la messagerie (déconnexion « back-channel ») ;
        # on supprime ensuite directement tout appareil restant, par sécurité.
        self.identite.fermer_sessions(u)
        provisoire = mot_de_passe_provisoire()
        self.identite.nouveau_mot_de_passe_provisoire(u, provisoire)
        # L'ancien second facteur (peut-être sur le téléphone volé) est remplacé par un nouveau,
        # remis à l'agent avec le mot de passe provisoire.
        secret = nouveau_secret()
        facteurs = self.identite.remplacer_second_facteur(u, secret)
        self.messagerie.deconnecter_appareils(mxid)
        self.journal.noter("urgence", "critique", auteur, identifiant,
                           f"Bouton d'urgence : {appareils} appareil(s) déconnecté(s), "
                           f"{facteurs} second facteur remplacé, nouveau mot de passe provisoire")
        return appareils, provisoire, cle_base32(secret)

    # ------------------------------------------------------------------ habilitations
    def habiliter(self, auteur: str, identifiant: str, habilite: bool) -> None:
        u = self.identite.exiger_utilisateur(identifiant)
        if habilite:
            self.identite.ajouter_au_groupe(u, self.r.groupe_habilites)
        else:
            self.identite.retirer_du_groupe(u, self.r.groupe_habilites)
        self.synchroniser_habilitations()
        self.journal.noter("habilitation", "info", auteur, identifiant,
                           "Habilitation CONFIDENTIEL accordée" if habilite else "Habilitation CONFIDENTIEL retirée")

    def synchroniser_habilitations(self) -> int:
        """Écrit la liste lue par le module de sécurité du serveur (écriture atomique)."""
        habilites = sorted(self.r.identifiant_matrix(u["username"])
                           for u in self.identite.membres(self.r.groupe_habilites) if u.get("enabled"))
        os.makedirs(self.r.dossier_journal, exist_ok=True)
        temporaire = self.fichier_habilitations + ".tmp"
        with open(temporaire, "w", encoding="utf-8") as f:
            json.dump({"confidentiel": habilites}, f, ensure_ascii=False, indent=2)
        os.replace(temporaire, self.fichier_habilitations)
        return len(habilites)
