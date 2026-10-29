"""Affiche le code du second facteur (TOTP) d'un compte de DÉMONSTRATION.

Pour la démo uniquement : un vrai agent utilise une application sur son téléphone
(FreeOTP, Aegis, Google Authenticator…). Usage : python3 outils/code_totp.py awa.sawadogo
"""

import base64
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
    return base64.b32encode(secret.encode()).decode().rstrip("=")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in SECRETS_DEMO:
        sys.exit("Comptes : " + ", ".join(SECRETS_DEMO))
    cle = cle_base32(SECRETS_DEMO[sys.argv[1]])
    reste = 30 - int(time.time()) % 30
    print(f"Code : {pyotp.TOTP(cle).now()}   (valable encore {reste} s)")
    print(f"Clé à saisir dans une application TOTP : {cle}")
