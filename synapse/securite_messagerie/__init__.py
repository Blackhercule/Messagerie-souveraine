"""Module de sécurité de la messagerie souveraine, chargé par le serveur Synapse.

Règles appliquées PAR LE SERVEUR, quel que soit le client utilisé :

1. Aucun message en clair : tout message non chiffré est refusé. Le serveur n'accepte
   que des messages chiffrés de bout en bout (événements « m.room.encrypted »), et le
   chiffrement d'un salon ne peut être ni retiré ni remplacé par un autre algorithme.
2. Classification des salons, d'après le début de leur nom :
      « [DIFFUSION RESTREINTE] … »  ou  « [CONFIDENTIEL] … »
   - les messages expirent automatiquement (durée de conservation maximale imposée) ;
   - un salon CONFIDENTIEL n'accepte que des agents habilités ;
   - un salon ne peut pas être déclassé.
3. Journal de sécurité : chaque refus est noté dans un fichier lu par la console de sécurité.

Ce module ne fait AUCUNE cryptographie. Le chiffrement de bout en bout est assuré par le
protocole Matrix (Olm/Megolm) dans les applications des agents ; le serveur ne voit que
des messages déjà chiffrés.
"""

import json
import logging
import os
import re
import threading
from datetime import datetime, timezone

from synapse.module_api import NOT_SPAM, ModuleApi
from synapse.module_api.errors import Codes

logger = logging.getLogger(__name__)

# Niveaux de classification, du plus bas au plus haut.
NORMAL = 0
DIFFUSION_RESTREINTE = 1
CONFIDENTIEL = 2
NOMS_NIVEAUX = {NORMAL: "normal", DIFFUSION_RESTREINTE: "diffusion restreinte", CONFIDENTIEL: "confidentiel"}

# Types d'événements qui contiennent du texte ou des fichiers : ils doivent être chiffrés.
TYPES_EN_CLAIR_INTERDITS = {"m.room.message", "m.sticker", "m.poll.start", "org.matrix.msc3381.poll.start"}

# Seul algorithme accepté pour les salons : Megolm, défini par la spécification Matrix.
ALGORITHME_SALONS = "m.megolm.v1.aes-sha2"

_DUREE = re.compile(r"^\s*(\d+)\s*([smhdj])\s*$")
_MS = {"s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000, "j": 86_400_000}


def duree_en_ms(texte: str) -> int:
    """« 7d » ou « 7j » → 604 800 000 millisecondes."""
    m = _DUREE.match(str(texte))
    if not m:
        raise ValueError(f"Durée invalide : {texte!r} (exemples : 12h, 7d, 30j)")
    return int(m.group(1)) * _MS[m.group(2)]


def niveau_du_nom(nom) -> int:
    """Niveau de classification d'un salon d'après le début de son nom."""
    if not isinstance(nom, str):
        return NORMAL
    debut = nom.strip().upper()
    if debut.startswith("[CONFIDENTIEL]"):
        return CONFIDENTIEL
    if debut.startswith("[DIFFUSION RESTREINTE]") or debut.startswith("[DR]"):
        return DIFFUSION_RESTREINTE
    return NORMAL


class ModuleSecurite:
    """Point d'entrée déclaré dans homeserver.yaml (section « modules »)."""

    def __init__(self, config: dict, api: ModuleApi):
        self._api = api
        dossier = config.get("dossier_journal", "/journal")
        self._fichier_journal = os.path.join(dossier, "evenements-serveur.jsonl")
        self._fichier_habilitations = os.path.join(dossier, "habilitations.json")
        self._durees_max = {
            DIFFUSION_RESTREINTE: duree_en_ms(config.get("conservation_diffusion_restreinte", "30d")),
            CONFIDENTIEL: duree_en_ms(config.get("conservation_confidentiel", "7d")),
        }
        self._verrou = threading.Lock()
        self._habilites: set = set()
        self._date_habilitations = None

        api.register_spam_checker_callbacks(
            check_event_for_spam=self.verifier_evenement,
            user_may_invite=self.peut_inviter,
            user_may_join_room=self.peut_rejoindre,
        )
        api.register_third_party_rules_callbacks(
            check_event_allowed=self.verifier_changement_etat,
            on_new_event=self.apres_evenement,
        )

    @staticmethod
    def parse_config(config: dict) -> dict:
        return config or {}

    # ------------------------------------------------------------------ règle 1
    async def verifier_evenement(self, event):
        """Refuse tout message envoyé en clair."""
        if event.type in TYPES_EN_CLAIR_INTERDITS and not event.is_state():
            self.journaliser("message_en_clair_refuse", event.sender, event.room_id,
                             f"type {event.type} refusé : seuls les messages chiffrés sont acceptés")
            return Codes.FORBIDDEN
        return NOT_SPAM

    # ------------------------------------------------------------------ règle 2
    async def peut_inviter(self, inviteur: str, invite: str, salon: str):
        return await self._controle_acces(invite, salon, f"invitation par {inviteur}")

    async def peut_rejoindre(self, utilisateur: str, salon: str, est_invite: bool):
        return await self._controle_acces(utilisateur, salon, "entrée dans le salon")

    async def _controle_acces(self, utilisateur: str, salon: str, action: str):
        if await self.niveau_salon(salon) == CONFIDENTIEL and not self.est_habilite(utilisateur):
            self.journaliser("acces_confidentiel_refuse", utilisateur, salon,
                             f"{action} refusée : agent non habilité au niveau CONFIDENTIEL")
            return Codes.FORBIDDEN
        return NOT_SPAM

    async def verifier_changement_etat(self, event, etat: dict):
        """Contrôle les changements de nom (classification) et de durée de conservation."""
        if not event.is_state():
            return True, None
        if event.type == "m.room.encryption" and event.content.get("algorithm") != ALGORITHME_SALONS:
            self.journaliser("chiffrement_modifie_refuse", event.sender, event.room_id,
                             f"algorithme {event.content.get('algorithm')!r} refusé : seul Megolm est accepté")
            return False, None
        niveau_actuel = niveau_du_nom(_contenu(etat.get(("m.room.name", ""))).get("name"))

        if event.type == "m.room.name":
            nouveau = niveau_du_nom(event.content.get("name"))
            if nouveau < niveau_actuel:
                self.journaliser("declassement_refuse", event.sender, event.room_id,
                                 f"tentative de passer de « {NOMS_NIVEAUX[niveau_actuel]} » "
                                 f"à « {NOMS_NIVEAUX[nouveau]} »")
                return False, None
            if nouveau == CONFIDENTIEL and niveau_actuel < CONFIDENTIEL:
                non_habilites = [cle[1] for cle, ev in etat.items()
                                 if cle[0] == "m.room.member"
                                 and _contenu(ev).get("membership") in ("join", "invite")
                                 and not self.est_habilite(cle[1])]
                if not self.est_habilite(event.sender):
                    non_habilites.append(event.sender)
                if non_habilites:
                    self.journaliser("classification_refusee", event.sender, event.room_id,
                                     "membres non habilités : " + ", ".join(sorted(set(non_habilites))))
                    return False, None

        if event.type == "m.room.retention" and niveau_actuel > NORMAL:
            duree = event.content.get("max_lifetime")
            if not isinstance(duree, int) or duree > self._durees_max[niveau_actuel]:
                self.journaliser("conservation_refusee", event.sender, event.room_id,
                                 f"durée de conservation supérieure au maximum du niveau "
                                 f"« {NOMS_NIVEAUX[niveau_actuel]} »")
                return False, None
        return True, None

    async def apres_evenement(self, event, etat: dict):
        """Quand un salon est classifié, impose sa durée de conservation (expiration automatique)."""
        if event.type != "m.room.name" or not event.is_state():
            return
        niveau = niveau_du_nom(event.content.get("name"))
        if niveau == NORMAL:
            return
        duree_max = self._durees_max[niveau]
        actuelle = _contenu(etat.get(("m.room.retention", ""))).get("max_lifetime")
        if isinstance(actuelle, int) and actuelle <= duree_max:
            return
        try:
            await self._api.create_and_send_event_into_room({
                "type": "m.room.retention",
                "room_id": event.room_id,
                "sender": event.sender,
                "state_key": "",
                "content": {"max_lifetime": duree_max},
            })
            self.journaliser("classification_appliquee", event.sender, event.room_id,
                             f"niveau « {NOMS_NIVEAUX[niveau]} », messages conservés "
                             f"{duree_max // 86_400_000} jour(s) au plus")
        except Exception as e:  # le refus éventuel est déjà journalisé
            logger.warning("Impossible d'imposer la conservation dans %s : %s", event.room_id, e)

    async def niveau_salon(self, salon: str) -> int:
        etat = await self._api.get_room_state(salon, [("m.room.name", "")])
        return niveau_du_nom(_contenu(etat.get(("m.room.name", ""))).get("name"))

    # ------------------------------------------------------------------ habilitations
    def est_habilite(self, utilisateur: str) -> bool:
        """Liste tenue à jour par la console de sécurité (groupe Keycloak « habilites-confidentiel »)."""
        try:
            date = os.path.getmtime(self._fichier_habilitations)
        except OSError:
            return False  # pas de liste : personne n'est habilité (on refuse par défaut)
        if date != self._date_habilitations:
            try:
                with open(self._fichier_habilitations, encoding="utf-8") as f:
                    self._habilites = set(json.load(f).get("confidentiel", []))
                self._date_habilitations = date
            except (OSError, ValueError) as e:
                logger.warning("Liste d'habilitations illisible : %s", e)
                return False
        return utilisateur in self._habilites

    # ------------------------------------------------------------------ règle 3
    def journaliser(self, type_evenement: str, utilisateur: str, salon: str, detail: str):
        ligne = {
            "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source": "serveur",
            "type": type_evenement,
            "utilisateur": utilisateur,
            "salon": salon,
            "detail": detail,
        }
        logger.info("Sécurité : %s", ligne)
        try:
            with self._verrou, open(self._fichier_journal, "a", encoding="utf-8") as f:
                f.write(json.dumps(ligne, ensure_ascii=False) + "\n")
        except OSError as e:
            logger.error("Journal de sécurité inaccessible : %s", e)


def _contenu(evenement) -> dict:
    return evenement.content if evenement is not None else {}
