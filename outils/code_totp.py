"""Affiche le code à 6 chiffres (TOTP) d'un compte, pour la DÉMONSTRATION.

Un vrai agent garde sa clé dans une application libre et hors ligne sur son téléphone (FreeOTP,
Aegis) : ce script joue seulement le rôle de ce téléphone pendant la démo.

    python outils/code_totp.py awa.sawadogo
        code d'un compte de démonstration, ou d'un agent enregistré ci-dessous

    python outils/code_totp.py --enregistrer fatima.kabore KF2E KUDH OA4F ...
        enregistre un agent enrôlé depuis la console : la clé est celle affichée sous le QR code
        (page « Agent enrôlé » ou « Appareils coupés »), espaces compris

    python outils/code_totp.py --liste
        agents connus du script

    python outils/code_totp.py KF2E KUDH OA4F ...
        code d'une clé donnée directement, sans l'enregistrer

Les clés enregistrées sont gardées dans outils/cles-demo.local.json, sur CET ordinateur
seulement (fichier ignoré par Git). À supprimer après la démonstration.
"""

import base64
import binascii
import json
import os
import sys
import time

try:
    import pyotp
except ImportError:
    sys.exit("Installez d'abord pyotp : pip install pyotp")

FICHIER_LOCAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cles-demo.local.json")

# Secrets fictifs des comptes de démonstration (keycloak/realm-administration.json).
SECRETS_DEMO = {
    "admin.securite": "DemoAdminSecu2026!!",
    "awa.sawadogo": "DemoAwaSawadogo2026",
    "issouf.ouedraogo": "DemoIssoufOuedrao26",
    "fatou.zongo": "DemoFatouZongo2026!",
    "moussa.sanou": "DemoMoussaSanou2026",
    "visiteur.externe": "DemoVisiteurExt2026",
}


def cle_base32(secret: str) -> str:
    """Keycloak stocke le secret brut des comptes de démo ; les applications utilisent sa forme Base32."""
    return base64.b32encode(secret.encode()).decode().rstrip("=")


def cle_saisie(morceaux: list) -> str:
    """Clé recopiée depuis la console : « kf2e kudh … » → « KF2EKUDH… » (espaces et tirets ignorés)."""
    cle = "".join(morceaux).replace(" ", "").replace("-", "").upper()
    try:
        base64.b32decode(cle + "=" * (-len(cle) % 8))
    except (binascii.Error, ValueError):
        sys.exit(f"Clé invalide : « {' '.join(morceaux)} ». Recopiez la clé affichée sous le QR code "
                 "(lettres A à Z et chiffres 2 à 7).")
    if len(cle) < 16:
        sys.exit("Clé trop courte : recopiez-la en entier.")
    return cle


def cles_locales() -> dict:
    try:
        with open(FICHIER_LOCAL, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except ValueError:
        sys.exit(f"Fichier illisible : {FICHIER_LOCAL}")


def enregistrer(identifiant: str, cle: str) -> None:
    if identifiant in SECRETS_DEMO:
        sys.exit(f"« {identifiant} » est un compte de démonstration : sa clé est déjà connue.")
    cles = cles_locales()
    cles[identifiant] = cle
    # Lisible par l'utilisateur seulement (sous Linux et macOS ; sous Windows, droits du dossier).
    descripteur = os.open(FICHIER_LOCAL, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descripteur, "w", encoding="utf-8") as f:
        json.dump(cles, f, indent=2, ensure_ascii=False)
    print(f"Agent « {identifiant} » enregistré. Ensuite : python outils/code_totp.py {identifiant}")


def afficher_code(cle: str) -> None:
    totp = pyotp.TOTP(cle)  # norme RFC 6238 : SHA-1, 6 chiffres, 30 secondes (réglages du royaume)
    maintenant = time.time()
    reste = 30 - int(maintenant) % 30
    print(f"Code : {totp.at(maintenant)}   (valable encore {reste} s ; code suivant : {totp.at(maintenant + 30)})")
    if reste < 8:
        print("Moins de 8 secondes : attendez le code suivant avant de le taper.")


def usage():
    sys.exit(__doc__.strip())


if __name__ == "__main__":
    arguments = [a for a in sys.argv[1:] if a != "--cle"]
    if not arguments or arguments[0] in ("-h", "--aide", "--help"):
        usage()
    if arguments[0] == "--liste":
        print("Comptes de démonstration : " + ", ".join(SECRETS_DEMO))
        locaux = cles_locales()
        print("Agents enregistrés sur cet ordinateur : " + (", ".join(locaux) if locaux else "aucun"))
    elif arguments[0] == "--enregistrer":
        if len(arguments) < 3:
            sys.exit("Usage : python outils/code_totp.py --enregistrer prenom.nom CLE AFFICHEE PAR LA CONSOLE")
        cle = cle_saisie(arguments[2:])
        enregistrer(arguments[1], cle)
        afficher_code(cle)
    elif len(arguments) == 1 and arguments[0] in SECRETS_DEMO:
        afficher_code(cle_base32(SECRETS_DEMO[arguments[0]]))
    elif len(arguments) == 1 and arguments[0] in cles_locales():
        afficher_code(cles_locales()[arguments[0]])
    elif len(arguments) == 1 and "." in arguments[0]:
        sys.exit(f"Agent inconnu du script : « {arguments[0]} ». Enregistrez-le d'abord avec la clé affichée "
                 f"par la console :\n  python outils/code_totp.py --enregistrer {arguments[0]} CLE")
    else:
        afficher_code(cle_saisie(arguments))
