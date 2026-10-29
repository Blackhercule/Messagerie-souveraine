"""Démarrage du conteneur Synapse.

1. Produit /data/homeserver.yaml à partir du modèle et des variables du fichier .env.
2. Crée la clé de signature du serveur si elle n'existe pas encore.
3. Donne les fichiers à l'utilisateur de Synapse, puis lance le démarrage officiel de l'image.
"""

import os
import shutil
import string
import subprocess
import sys

MODELE = "/config-modele/homeserver.yaml.modele"
CONFIG = "/data/homeserver.yaml"
UID = int(os.environ.get("UID", "991"))
GID = int(os.environ.get("GID", "991"))


def produire_configuration():
    with open(MODELE, encoding="utf-8") as f:
        modele = string.Template(f.read())
    try:
        texte = modele.substitute(os.environ)  # erreur claire si une variable manque
    except KeyError as e:
        sys.exit(f"Variable manquante dans le fichier .env : {e}")
    with open(CONFIG, "w", encoding="utf-8") as f:
        f.write(texte)
    shutil.copy("/config-modele/log.config", "/data/log.config")


def creer_cles():
    subprocess.run([sys.executable, "-m", "synapse.app.homeserver",
                    "--config-path", CONFIG, "--generate-keys"], check=True)


def donner_droits():
    for dossier in ("/data", "/journal"):
        os.makedirs(dossier, exist_ok=True)
        for racine, dossiers, fichiers in os.walk(dossier):
            for nom in [racine] + [os.path.join(racine, n) for n in dossiers + fichiers]:
                os.chown(nom, UID, GID)


if __name__ == "__main__":
    produire_configuration()
    creer_cles()
    donner_droits()
    os.environ["SYNAPSE_CONFIG_PATH"] = CONFIG
    os.execv(sys.executable, [sys.executable, "/start.py"])
