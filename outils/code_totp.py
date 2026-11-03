"""Affiche le code à 6 chiffres (TOTP) d'un compte, pour la DÉMONSTRATION.

Un vrai agent utilise une application libre et hors ligne sur son téléphone (FreeOTP, Aegis) :
ce script joue seulement le rôle de ce téléphone pendant la démo.

    python outils/code_totp.py awa.sawadogo              compte de démonstration
    python outils/code_totp.py JBSW Y3DP EHPK 3PXP ...   NOUVEL agent enrôlé depuis la console :
                                                         la clé affichée par Keycloak sous le QR code
                                                         (lien « Impossible de scanner ? »), espaces compris
"""

import base64
import binascii
import sys
import time

try:
    import pyotp
except ImportError:
    sys.exit("Installez d'abord pyotp : pip install pyotp")

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
    """Clé recopiée depuis Keycloak : « jbsw y3dp … » → « JBSWY3DP… » (espaces et tirets ignorés)."""
    cle = "".join(morceaux).replace(" ", "").replace("-", "").upper()
    try:
        base64.b32decode(cle + "=" * (-len(cle) % 8))
    except (binascii.Error, ValueError):
        sys.exit(f"Clé invalide : « {' '.join(morceaux)} ». Recopiez la clé affichée sous le QR code "
                 "(lettres A à Z et chiffres 2 à 7).")
    if len(cle) < 16:
        sys.exit("Clé trop courte : recopiez-la en entier.")
    return cle


def usage():
    sys.exit(__doc__.strip() + "\n\nComptes de démonstration : " + ", ".join(SECRETS_DEMO))


if __name__ == "__main__":
    arguments = [a for a in sys.argv[1:] if a != "--cle"]
    if not arguments:
        usage()
    if len(arguments) == 1 and arguments[0] in SECRETS_DEMO:
        cle = cle_base32(SECRETS_DEMO[arguments[0]])
    elif len(arguments) == 1 and "." in arguments[0]:
        sys.exit(f"« {arguments[0]} » n'est pas un compte de démonstration. Pour un agent enrôlé depuis la "
                 "console, donnez la clé affichée par Keycloak sous le QR code.")
    else:
        cle = cle_saisie(arguments)
    totp = pyotp.TOTP(cle)  # norme RFC 6238 : SHA-1, 6 chiffres, 30 secondes (réglages du royaume)
    maintenant = time.time()
    reste = 30 - int(maintenant) % 30
    print(f"Code : {totp.at(maintenant)}   (valable encore {reste} s ; code suivant : {totp.at(maintenant + 30)})")
    if reste < 8:
        print("Moins de 8 secondes : attendez le code suivant avant de le taper.")
    print(f"Clé : {cle}")
