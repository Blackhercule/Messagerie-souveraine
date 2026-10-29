"""Navigateur minimal pour les tests : suit la connexion Keycloak comme le ferait un agent.

Il remplit les formulaires de Keycloak (identifiant, mot de passe, code TOTP) et sait aussi
traiter la première connexion d'un agent enrôlé (nouveau mot de passe + enregistrement du TOTP).
Le TLS est VÉRIFIÉ avec l'autorité de certification interne de la messagerie.
"""

import base64
import html
import os
import re
import time
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

import pyotp
import requests

ADRESSE = os.environ.get("ADRESSE_PUBLIQUE", "https://localhost:8443").rstrip("/")
CA_RACINE = os.environ.get("CA_RACINE", os.path.join(os.path.dirname(__file__), "..", "ca-messagerie.crt"))
NOM_SERVEUR = os.environ.get("NOM_SERVEUR_MATRIX", "messagerie.local")

# Keycloak refuse qu'un même code TOTP serve deux fois : on garde la trace des codes déjà utilisés.
_codes_utilises = {}


def cle_totp_depuis_secret(secret_brut: str) -> str:
    """Keycloak stocke le secret brut ; les applications TOTP utilisent son encodage Base32."""
    return base64.b32encode(secret_brut.encode()).decode().rstrip("=")


def code_totp(cle_base32: str) -> str:
    totp = pyotp.TOTP(cle_base32)
    deja = _codes_utilises.setdefault(cle_base32, set())
    while True:
        maintenant = time.time()
        # Keycloak accepte la fenêtre courante et ses voisines (otpPolicyLookAheadWindow = 1).
        for decalage in (0, 30, -30):
            code = totp.at(maintenant + decalage)
            if code not in deja:
                deja.add(code)
                return code
        time.sleep(31 - maintenant % 30)


class _Formulaires(HTMLParser):
    def __init__(self):
        super().__init__()
        self.formulaires, self._courant = [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._courant = {"id": a.get("id", ""), "action": html.unescape(a.get("action", "")), "champs": {}}
            self.formulaires.append(self._courant)
        elif tag == "input" and self._courant is not None and a.get("name"):
            self._courant["champs"][a["name"]] = a.get("value") or ""

    def handle_endtag(self, tag):
        if tag == "form":
            self._courant = None


def formulaires(page: str) -> dict:
    p = _Formulaires()
    p.feed(page)
    return {f["id"]: f for f in p.formulaires}


class EchecConnexion(Exception):
    def __init__(self, etape: str, page: str = ""):
        message = re.search(r'id="input-error[^"]*"[^>]*>\s*([^<]+)', page) or \
            re.search(r'class="[^"]*(?:alert|kc-feedback-text)[^"]*"[^>]*>\s*([^<]+)', page)
        self.etape = etape
        self.message = message.group(1).strip() if message else ""
        super().__init__(f"{etape} : {self.message}")


class Navigateur:
    def __init__(self):
        self.s = requests.Session()
        self.s.trust_env = False      # pas de mandataire : on parle directement au serveur
        self.s.verify = CA_RACINE     # certificat vérifié avec l'autorité interne
        self.nouveau_mot_de_passe = None
        self.nouvelle_cle_totp = None

    def connexion_keycloak(self, depart: str, nom: str, mot_de_passe: str, cle_totp: str = None,
                           code_force: str = None, mot_de_passe_final: str = None):
        """Ouvre `depart`, s'authentifie sur Keycloak et renvoie la dernière réponse HTTP."""
        rep = self.s.get(depart)
        f = formulaires(rep.text).get("kc-form-login")
        if f is None:
            raise EchecConnexion("page de connexion absente", rep.text)
        rep = self.s.post(f["action"], data={"username": nom, "password": mot_de_passe, "credentialId": ""})
        for _ in range(4):
            formes = formulaires(rep.text)
            if "kc-otp-login-form" in formes:
                code = code_force or (code_totp(cle_totp) if cle_totp else "")
                rep = self.s.post(formes["kc-otp-login-form"]["action"], data={"otp": code, "login": "Connexion"})
                if "kc-otp-login-form" in formulaires(rep.text) and cle_totp and not code_force:
                    # Code déjà utilisé par un test précédent (Keycloak interdit la réutilisation) :
                    # on attend la fenêtre de 30 s suivante, comme le ferait un agent.
                    time.sleep(31 - time.time() % 30)
                    rep = self.s.post(formulaires(rep.text)["kc-otp-login-form"]["action"],
                                      data={"otp": code_totp(cle_totp), "login": "Connexion"})
                if "kc-otp-login-form" in formulaires(rep.text):
                    raise EchecConnexion("code TOTP refusé", rep.text)
            elif "kc-passwd-update-form" in formes:
                self.nouveau_mot_de_passe = mot_de_passe_final or f"Agent-{int(time.time())}-Valide!"
                rep = self.s.post(formes["kc-passwd-update-form"]["action"], data={
                    "password-new": self.nouveau_mot_de_passe, "password-confirm": self.nouveau_mot_de_passe})
            elif "kc-totp-settings-form" in formes:
                champs = formes["kc-totp-settings-form"]["champs"]
                self.nouvelle_cle_totp = cle_totp_depuis_secret(champs["totpSecret"])
                rep = self.s.post(formes["kc-totp-settings-form"]["action"], data={
                    **champs, "totp": code_totp(self.nouvelle_cle_totp), "userLabel": "Téléphone de test"})
            elif "kc-form-login" in formes:
                raise EchecConnexion("identifiants refusés", rep.text)
            else:
                return rep
        return rep

    # ------------------------------------------------------------------ messagerie
    def connexion_matrix(self, nom, mot_de_passe, cle_totp=None, **kwargs) -> "ClientMatrix":
        depart = (f"{ADRESSE}/_matrix/client/v3/login/sso/redirect/oidc-administration"
                  f"?redirectUrl={ADRESSE}/")
        rep = self.connexion_keycloak(depart, nom, mot_de_passe, cle_totp, **kwargs)
        jeton = parse_qs(urlparse(rep.url).query).get("loginToken")
        if not jeton:
            raise EchecConnexion(f"messagerie refusée (HTTP {rep.status_code})", rep.text)
        for _ in range(10):
            r = self.s.post(f"{ADRESSE}/_matrix/client/v3/login",
                            json={"type": "m.login.token", "token": jeton[0],
                                  "initial_device_display_name": "Tests automatisés"})
            if r.status_code != 429:
                break
            time.sleep(r.json().get("retry_after_ms", 1000) / 1000 + 0.1)
        r.raise_for_status()
        return ClientMatrix(self.s, r.json())

    # ------------------------------------------------------------------ console
    def connexion_console(self, nom, mot_de_passe, cle_totp):
        return self.connexion_keycloak(f"{ADRESSE}/console/connexion", nom, mot_de_passe, cle_totp)

    def jeton_csrf(self, page: str) -> str:
        return re.search(r'name="jeton_csrf" value="([^"]+)"', page).group(1)

    def poster_console(self, chemin: str, page_formulaire: str, donnees: dict):
        return self.s.post(urljoin(ADRESSE, chemin), data={"jeton_csrf": self.jeton_csrf(page_formulaire), **donnees})


class ClientMatrix:
    """Appels directs à l'API Matrix des applications (comme Element ou l'application mobile)."""

    def __init__(self, session: requests.Session, connexion: dict):
        self.s = session
        self.jeton = connexion["access_token"]
        self.identifiant = connexion["user_id"]
        self.appareil = connexion["device_id"]
        self._txn = 0

    def appel(self, methode, chemin, **kwargs):
        for _ in range(10):
            r = self.s.request(methode, f"{ADRESSE}/_matrix/client/v3{chemin}",
                               headers={"Authorization": f"Bearer {self.jeton}"}, **kwargs)
            if r.status_code != 429:  # limite de débit du serveur (anti-abus) : on patiente
                return r
            time.sleep(r.json().get("retry_after_ms", 1000) / 1000 + 0.1)
        return r

    def ok(self, methode, chemin, **kwargs) -> dict:
        r = self.appel(methode, chemin, **kwargs)
        assert r.status_code == 200, f"{methode} {chemin} → {r.status_code} {r.text[:300]}"
        return r.json()

    def creer_salon(self, nom: str, invites=()) -> str:
        return self.ok("POST", "/createRoom", json={"name": nom, "preset": "private_chat",
                                                     "invite": list(invites)})["room_id"]

    def etat(self, salon: str, type_evenement: str, cle: str = ""):
        r = self.appel("GET", f"/rooms/{salon}/state/{type_evenement}/{cle}")
        return r.json() if r.status_code == 200 else None

    def envoyer(self, salon: str, type_evenement: str, contenu: dict):
        self._txn += 1
        return self.appel("PUT", f"/rooms/{salon}/send/{type_evenement}/t{time.time_ns()}{self._txn}",
                          json=contenu)

    def changer_etat(self, salon: str, type_evenement: str, contenu: dict, cle: str = ""):
        return self.appel("PUT", f"/rooms/{salon}/state/{type_evenement}/{cle}", json=contenu)

    def rejoindre(self, salon: str):
        return self.appel("POST", f"/join/{salon}", json={})

    def inviter(self, salon: str, identifiant: str):
        return self.appel("POST", f"/rooms/{salon}/invite", json={"user_id": identifiant})

    def membres(self, salon: str) -> dict:
        evts = self.ok("GET", f"/rooms/{salon}/members")["chunk"]
        return {e["state_key"]: e["content"]["membership"] for e in evts}


def mxid(nom: str) -> str:
    return f"@{nom}:{NOM_SERVEUR}"
