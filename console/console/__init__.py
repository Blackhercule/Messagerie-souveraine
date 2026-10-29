"""Console de sécurité de la messagerie souveraine (application Flask).

Réservée aux agents ayant le rôle « administrateur-securite » dans Keycloak ;
la connexion passe par Keycloak, donc avec le second facteur (TOTP).
"""

import functools
import logging
import secrets
import threading
import time
from datetime import timedelta

from authlib.integrations.flask_client import OAuth
from flask import Blueprint, Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from .identite import ErreurIdentite
from .messagerie import ErreurMessagerie
from .operations import ErreurOperation, Operations
from .reglages import Reglages

vues = Blueprint("console", __name__, url_prefix="/console", static_folder="static", static_url_path="/static")
oauth = OAuth()


def creer_application(reglages: Reglages = None) -> Flask:
    reglages = reglages or Reglages()
    app = Flask(__name__, static_folder=None)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    app.config.update(
        SECRET_KEY=reglages.secret_session,
        SESSION_COOKIE_NAME="console_securite",
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_PATH="/console",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    )
    app.extensions["reglages"] = reglages
    app.extensions["operations"] = Operations(reglages)
    _synchronisation_periodique(app.extensions["operations"])

    oauth.init_app(app)
    oauth.register(
        "keycloak",
        client_id=reglages.client_id,
        client_secret=reglages.client_secret,
        # Le navigateur passe par l'adresse publique ; la console joint Keycloak en interne.
        authorize_url=f"{reglages.emetteur_oidc}/protocol/openid-connect/auth",
        access_token_url=f"{reglages.oidc_interne}/token",
        jwks_uri=f"{reglages.oidc_interne}/certs",
        issuer=reglages.emetteur_oidc,
        client_kwargs={"scope": "openid profile", "code_challenge_method": "S256"},
    )
    app.register_blueprint(vues)

    @app.after_request
    def entetes_securite(reponse):
        reponse.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'none'; frame-ancestors 'none'; form-action 'self'")
        reponse.headers["X-Frame-Options"] = "DENY"
        reponse.headers["Cache-Control"] = "no-store"
        return reponse

    return app


def _synchronisation_periodique(operations: Operations, intervalle: int = 60) -> None:
    """Recopie régulièrement les habilitations de Keycloak vers le serveur de messagerie.

    Ainsi une habilitation changée directement dans Keycloak est aussi prise en compte,
    et la liste existe dès le démarrage (sans elle, le serveur refuse tout accès CONFIDENTIEL).
    """
    def boucle():
        while True:
            try:
                operations.synchroniser_habilitations()
            except Exception as e:  # Keycloak pas encore prêt : on réessaiera
                logging.getLogger(__name__).warning("Synchronisation des habilitations : %s", e)
            time.sleep(intervalle)
    threading.Thread(target=boucle, name="habilitations", daemon=True).start()


def ops() -> Operations:
    from flask import current_app
    return current_app.extensions["operations"]


def reglages() -> Reglages:
    from flask import current_app
    return current_app.extensions["reglages"]


# ---------------------------------------------------------------------- sécurité des pages
def administrateur_requis(vue):
    @functools.wraps(vue)
    def emballage(*args, **kwargs):
        if "admin" not in session:
            return redirect(url_for("console.connexion"))
        if request.method == "POST":
            jeton = request.form.get("jeton_csrf", "")
            if not secrets.compare_digest(jeton, session.get("jeton_csrf", "")):
                abort(400, "Jeton de formulaire invalide : rechargez la page.")
        return vue(*args, **kwargs)
    return emballage


@vues.app_context_processor
def variables_communes():
    if "jeton_csrf" not in session:
        session["jeton_csrf"] = secrets.token_urlsafe(32)
    return {"jeton_csrf": session["jeton_csrf"], "admin": session.get("admin"),
            "adresse_messagerie": reglages().adresse_publique}


# ---------------------------------------------------------------------- connexion
@vues.route("/connexion")
def connexion():
    retour = f"{reglages().adresse_publique}/console/connexion/retour"
    return oauth.keycloak.authorize_redirect(retour)


@vues.route("/connexion/retour")
def connexion_retour():
    jeton = oauth.keycloak.authorize_access_token()
    profil = jeton.get("userinfo") or {}
    if reglages().role_admin not in profil.get("roles", []):
        ops().journal.noter("acces_console_refuse", "intrus", profil.get("preferred_username", "?"), "console",
                            "Accès à la console refusé : rôle administrateur-securite absent")
        session.clear()
        return render_template("refus.html", nom=profil.get("preferred_username", "")), 403
    session.clear()
    session.permanent = True
    session["admin"] = {"nom": profil.get("preferred_username"), "nom_complet": profil.get("name", "")}
    session["id_token"] = jeton.get("id_token")
    return redirect(url_for("console.tableau"))


@vues.route("/deconnexion", methods=["POST"])
@administrateur_requis
def deconnexion():
    id_token = session.get("id_token", "")
    session.clear()
    fin = (f"{reglages().emetteur_oidc}/protocol/openid-connect/logout?id_token_hint={id_token}"
           f"&post_logout_redirect_uri={reglages().adresse_publique}/console/")
    return redirect(fin)


# ---------------------------------------------------------------------- pages
@vues.route("/")
@administrateur_requis
def tableau():
    agents = ops().agents()
    journal = ops().journal_complet()
    ops().synchroniser_habilitations()
    return render_template("tableau.html", agents=agents, journal=journal[:8],
                           actifs=sum(1 for a in agents if a["actif"] and a["enrole"]),
                           revoques=sum(1 for a in agents if not a["actif"]),
                           habilites=sum(1 for a in agents if a["actif"] and a["habilite"]),
                           intrusions=sum(1 for l in journal if l["gravite"] == "intrus"))


@vues.route("/agents")
@administrateur_requis
def agents():
    return render_template("agents.html", agents=ops().agents())


@vues.route("/agents/nouveau", methods=["GET", "POST"])
@administrateur_requis
def enroler():
    if request.method == "GET":
        return render_template("enroler.html")
    f = request.form
    try:
        identifiant, provisoire = ops().enroler(session["admin"]["nom"], f.get("prenom", ""), f.get("nom", ""),
                                                f.get("ministere", ""), f.get("fonction", ""),
                                                f.get("habilite") == "oui")
    except (ErreurOperation, ErreurIdentite) as e:
        flash(str(e), "erreur")
        return render_template("enroler.html", formulaire=f), 400
    return render_template("identifiants.html", titre="Agent enrôlé", identifiant=identifiant,
                           provisoire=provisoire, explication="À la première connexion, l'agent choisit son "
                           "mot de passe et enregistre son second facteur (application TOTP).")


@vues.route("/agents/<identifiant>/revoquer", methods=["POST"])
@administrateur_requis
def revoquer(identifiant):
    try:
        resultat = ops().revoquer(session["admin"]["nom"], identifiant, request.form.get("motif") or "départ")
        flash(f"{identifiant} est révoqué : {resultat['appareils']} appareil(s) déconnecté(s) "
              f"en {resultat['duree_ms']} ms.", "succes")
    except (ErreurOperation, ErreurIdentite, ErreurMessagerie) as e:
        flash(f"Échec de la révocation : {e}", "erreur")
    return redirect(url_for("console.agents"))


@vues.route("/agents/<identifiant>/urgence", methods=["POST"])
@administrateur_requis
def urgence(identifiant):
    try:
        appareils, provisoire = ops().urgence(session["admin"]["nom"], identifiant)
    except (ErreurOperation, ErreurIdentite, ErreurMessagerie) as e:
        flash(f"Échec : {e}", "erreur")
        return redirect(url_for("console.agents"))
    return render_template("identifiants.html", titre="Appareils coupés", identifiant=identifiant,
                           provisoire=provisoire, explication=f"{appareils} appareil(s) déconnecté(s) et second "
                           "facteur supprimé. Remettez ce mot de passe provisoire à l'agent en main propre : "
                           "il réenregistrera son second facteur sur son nouveau téléphone.")


@vues.route("/agents/<identifiant>/habilitation", methods=["POST"])
@administrateur_requis
def habilitation(identifiant):
    try:
        ops().habiliter(session["admin"]["nom"], identifiant, request.form.get("habilite") == "oui")
        flash("Habilitation mise à jour.", "succes")
    except ErreurIdentite as e:
        flash(str(e), "erreur")
    return redirect(url_for("console.agents"))


@vues.route("/journal")
@administrateur_requis
def journal():
    filtre = request.args.get("gravite", "")
    lignes = ops().journal_complet()
    if filtre:
        lignes = [l for l in lignes if l["gravite"] == filtre]
    return render_template("journal.html", lignes=lignes[:300], filtre=filtre)


@vues.errorhandler(ErreurIdentite)
@vues.errorhandler(ErreurMessagerie)
def erreur_service(e):
    return render_template("erreur.html", message=str(e)), 502
