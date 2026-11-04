# Comptes de démonstration et scénario du jury

Tous ces comptes sont **fictifs** et n'existent que dans ce prototype. Les secrets ci-dessous
sont publics : ils ne doivent **jamais** servir dans un vrai déploiement (`./installer.sh
--reinitialiser` repart de zéro ; un vrai déploiement n'importe pas ces comptes).

## Comptes

| Identifiant | Mot de passe | Rôle dans la démo | Clé TOTP (Base32) |
|---|---|---|---|
| `admin.securite` | `Demo-Admin-2026` | Aminata Kaboré, administratrice sécurité : accès à la console | `IRSW232BMRWWS3STMVRXKMRQGI3CCII` |
| `awa.sawadogo` | `Demo-Awa-2026` | Agente habilitée CONFIDENTIEL | `IRSW232BO5QVGYLXMFSG6Z3PGIYDENQ` |
| `issouf.ouedraogo` | `Demo-Issouf-2026` | Agent habilité CONFIDENTIEL | `IRSW232JONZW65LGJ52WKZDSMFXTENQ` |
| `fatou.zongo` | `Demo-Fatou-2026` | Agente **non** habilitée | `IRSW232GMF2G65K2N5XGO3ZSGAZDMII` |
| `moussa.sanou` | `Demo-Moussa-2026` | Agent qui « quitte l'administration » (révocation) | `IRSW232NN52XG43BKNQW433VGIYDENQ` |
| `visiteur.externe` | `Demo-Visiteur-2026` | Identité valide mais **non enrôlée** : l'intrus | `IRSW232WNFZWS5DFOVZEK6DUGIYDENQ` |

**Obtenir le code à 6 chiffres** : scanner le QR code du compte (`docs/qr-totp/<compte>.png`)
avec une application TOTP **libre et sans compte en ligne** : FreeOTP (iPhone et Android,
licence Apache-2.0) ou Aegis (Android, licence GPL-3.0). Le code est calculé sur le téléphone,
sans réseau (norme ouverte TOTP, RFC 6238). Ou lancer
`python3 outils/code_totp.py awa.sawadogo`. Un même code ne peut servir qu'**une fois**.

**Agent enrôlé pendant la démo** (console → Enrôler) : la console crée le compte AVEC son second
facteur et affiche, une seule fois, le mot de passe provisoire, un QR code et la clé correspondante.
- Membre du jury avec un téléphone : il scanne le QR code avec son application TOTP, puis se connecte.
- Sans téléphone : enregistrer la clé affichée dans le script, une fois pour toutes, puis demander
  le code à chaque connexion :

```bash
python outils/code_totp.py --enregistrer fatima.kabore KF2E KUDH OA4F ...   # clé affichée par la console
python outils/code_totp.py fatima.kabore                                     # code du moment
python outils/code_totp.py --liste                                           # agents connus du script
```

Les clés enregistrées restent sur ce PC (`outils/cles-demo.local.json`, ignoré par Git) : à supprimer
après la démo. Dans un vrai déploiement, la clé n'existe que dans Keycloak et dans le téléphone de
l'agent. Le bouton « Téléphone perdu » remet de la même façon un nouveau QR code (l'ancien est
inutilisable) : enregistrer la nouvelle clé avec `--enregistrer`.

## Préparer la démonstration (10 minutes, la veille)

1. `./installer.sh 192.168.x.x` (adresse IP du PC sur le Wi-Fi) ; installer `ca-messagerie.crt`
   sur le PC et sur le téléphone de démonstration.
2. Ouvrir trois fenêtres : **Awa** (navigateur), **Issouf** (téléphone : application Element classique ou navigateur, serveur
   `https://192.168.x.x:8443`), **Moussa** (fenêtre de navigation privée).
3. Créer avec Awa un salon « Cellule budget 2027 », inviter Issouf, Fatou et Moussa.
4. Ouvrir la console de sécurité (`/console`, compte `admin.securite`).

## Changer de réseau (jour de la présentation)

Sur un autre Wi-Fi, l'adresse IP du PC change. **Ne pas réinitialiser** : il suffit de

```bash
./installer.sh --changer-adresse 10.x.x.x   # nouvelle adresse IP du PC (ipconfig)
```

Les comptes, les conversations et l'autorité de certification sont conservés : rien à
réinstaller sur le PC ni sur les téléphones. Ouvrir la nouvelle adresse et se reconnecter.
Ouvrir aussi le port 8443 dans le pare-feu du PC, et vérifier que le réseau laisse les appareils
communiquer entre eux (sinon, utiliser le partage de connexion d'un téléphone : la messagerie
n'a pas besoin d'Internet).

**Sans Internet le jour J** : faire `git pull` puis `docker compose up -d --build` la veille,
avec Internet. Le jour même, `--changer-adresse` réutilise les images déjà construites si la
reconstruction échoue faute d'Internet.

## Scénario de la vidéo (3 minutes)

| Temps | Ce qu'on montre | Ce qu'on dit |
|---|---|---|
| 0:00 | Connexion d'Awa : mot de passe puis code TOTP | « Seuls les agents enrôlés entrent, toujours avec un second facteur. » |
| 0:20 | `visiteur.externe` se connecte avec un bon mot de passe et un bon code : **refusé**. La console affiche « INTRUS ». | « Avoir un compte ne suffit pas : il faut avoir été enrôlé. » |
| 0:40 | Awa écrit dans « Cellule budget 2027 » : « Réunion jeudi à 9 h » ; Issouf lit sur son téléphone. | « Web et mobile, même conversation, chiffrée de bout en bout. » |
| 1:00 | `./outils/ce-que-voit-le-serveur.sh` puis `./outils/ce-que-voit-le-serveur.sh "jeudi"` → **0** | « Voici ce que stocke le serveur : du texte chiffré. Le mot du message n'y figure nulle part. » (Le nom du salon, lui, est visible : limite documentée de Matrix.) |
| 1:30 | Console → Moussa → **Révoquer**. Sa fenêtre est déconnectée aussitôt ; il disparaît du salon ; il ne peut plus se reconnecter. | « Un agent quitte l'administration : un clic, tous ses appareils sont coupés. » |
| 2:00 | Awa renomme un salon en `[CONFIDENTIEL] …` alors que Fatou y est : **refusé**. Avec Issouf seul : accepté, messages effacés après 7 jours. | « La classification est imposée par le serveur, pas par la bonne volonté. » |
| 2:30 | `cd tests && python -m pytest -q` : 41 tests verts. Journal de la console. | « Chaque garantie est vérifiée automatiquement. Tout est open source. » |

## Lancer les tests sur l'installation Docker

Prérequis : Python 3.10 ou plus récent, et Node.js (pour le test de chiffrement réel).
Les commandes fonctionnent dans Git Bash comme dans l'invite de commandes Windows.

```bash
pip install -r tests/requirements.txt
cd tests && python -m pytest -v
```

Résultat vérifié sur Windows 10 avec Docker Desktop : **41 passed** en 1 min 30 environ.
Juste après une installation, Keycloak et Synapse « démarrent à froid » : si le test de
révocation dépasse sa limite de 5 secondes au tout premier lancement, relancer la série.

Les tests créent des agents « Test … » dans l'annuaire. Pour une démonstration propre,
lancez-les **avant** `./installer.sh --reinitialiser`, ou après la vidéo.

## Captures (répétition du scénario sur une installation neuve)

| | |
|---|---|
| ![Second facteur](captures/1-connexion-second-facteur.jpg) Connexion : code TOTP exigé | ![Web](captures/2-conversation-web.jpg) Awa (navigateur) : salon chiffré |
| ![Mobile](captures/3-conversation-mobile.jpg) Issouf (téléphone) : même conversation | ![Révocation](captures/4-console-revocation.jpg) Console : Moussa révoqué, 2 appareils coupés |
| ![Déconnecté](captures/5-agent-revoque-deconnecte.jpg) Fenêtre de Moussa : déconnectée aussitôt | ![Journal](captures/6-journal-securite.jpg) Journal : intrus, révocation, classification refusée |
