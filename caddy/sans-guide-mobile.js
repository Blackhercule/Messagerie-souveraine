// Chargé par index.html AVANT Element Web (ajouté à la construction de l'image, voir Dockerfile).
//
// Sur un téléphone, Element Web envoie vers /mobile_guide/ (« téléchargez l'application ») toute
// adresse sans fragment #/… — y compris le RETOUR de la connexion SSO (/?loginToken=…). Le jeton
// était alors perdu et l'agent revenait à la page de connexion, en boucle.
// Element ne fait pas ce détour quand ce drapeau est présent : on le pose avant son démarrage.
try {
    sessionStorage.setItem("skip_mobile_redirect", "true");
} catch (e) {
    // Stockage indisponible : Caddy redirige quand même /mobile_guide/ vers la connexion.
}
