"""Second facteur (TOTP, norme ouverte RFC 6238) remis à l'agent lors de son enrôlement.

La console tire un secret au hasard, le confie à Keycloak (qui vérifie les codes) et l'affiche
UNE SEULE FOIS, en QR code, pour que l'agent l'enregistre dans son application (FreeOTP, Aegis…).
Le secret n'est conservé nulle part ailleurs que dans Keycloak et dans le téléphone de l'agent.

Aucune cryptographie écrite ici : le hasard vient du module standard « secrets », les codes sont
calculés par Keycloak et par l'application de l'agent.
"""

import base64
import secrets
import string
from urllib.parse import quote

import segno

EMETTEUR = "Messagerie souveraine"
_ALPHABET = string.ascii_letters + string.digits


def nouveau_secret() -> str:
    """20 caractères aléatoires (≈ 119 bits), comme les secrets que tire Keycloak lui-même."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(20))


def cle_base32(secret: str) -> str:
    """La forme du secret que saisissent les applications TOTP."""
    return base64.b32encode(secret.encode()).decode().rstrip("=")


def cle_lisible(cle: str) -> str:
    """« KF2EKUDHOA4F… » → « KF2E KUDH OA4F … », plus facile à recopier."""
    return " ".join(cle[i:i + 4] for i in range(0, len(cle), 4))


def lien_otpauth(identifiant: str, cle: str) -> str:
    """Le contenu du QR code, au format reconnu par toutes les applications TOTP."""
    return (f"otpauth://totp/{quote(EMETTEUR + ':' + identifiant)}?secret={cle}&issuer={quote(EMETTEUR)}"
            "&algorithm=SHA1&digits=6&period=30")


def qr_svg(lien: str) -> str:
    """QR code en SVG, inclus directement dans la page (aucun script, aucune requête extérieure)."""
    return segno.make(lien, error="m").svg_inline(scale=5, border=2, dark="#0b1f17", light="#ffffff",
                                                 title="QR code du second facteur")
