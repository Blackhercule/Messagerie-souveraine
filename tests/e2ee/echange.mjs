// Échange réellement chiffré de bout en bout entre deux agents (fictifs).
//
// Utilise la bibliothèque officielle Matrix (matrix-js-sdk) et son module de chiffrement
// Rust (vodozemac, implémentation de référence d'Olm/Megolm) : AUCUNE cryptographie écrite
// par l'équipe. Les jetons de connexion sont fournis par le test Python (connexion Keycloak
// avec mot de passe + TOTP), dans la variable d'environnement SESSIONS.
//
// Sortie : une ligne « RESULTAT {…} » (phrase, event_id, texte déchiffré par le destinataire).

import { randomBytes } from "node:crypto";
import * as sdk from "matrix-js-sdk";
import { logger } from "matrix-js-sdk/lib/logger.js";

logger.setLevel("error"); // la sortie standard ne doit contenir que le résultat

const adresse = process.env.ADRESSE_PUBLIQUE;
const sessions = JSON.parse(process.env.SESSIONS);

function attendre(condition, delaiMs, message) {
  return new Promise((resoudre, rejeter) => {
    const fin = Date.now() + delaiMs;
    const tour = async () => {
      try {
        const valeur = await condition();
        if (valeur) return resoudre(valeur);
      } catch { /* on réessaie */ }
      if (Date.now() > fin) return rejeter(new Error(`Délai dépassé : ${message}`));
      setTimeout(tour, 250);
    };
    tour();
  });
}

async function demarrer({ user_id, access_token, device_id }) {
  const client = sdk.createClient({ baseUrl: adresse, userId: user_id, accessToken: access_token, deviceId: device_id });
  await client.initRustCrypto({ useIndexedDB: false }); // clés gardées en mémoire, sur « l'appareil »
  await client.startClient({ initialSyncLimit: 5 });
  await new Promise((ok) => client.once(sdk.ClientEvent.Sync, ok));
  return client;
}

const expediteur = await demarrer(sessions.expediteur);
const destinataire = await demarrer(sessions.destinataire);

// 1. L'expéditrice crée un salon (chiffré automatiquement par le serveur) et invite son collègue.
const { room_id: salon } = await expediteur.createRoom({
  name: "Échange chiffré (test automatique)", preset: "private_chat", invite: [destinataire.getUserId()],
});
await attendre(() => destinataire.getRoom(salon)?.getMyMembership() === "invite", 20000, "invitation reçue");
await destinataire.joinRoom(salon);
await attendre(() => expediteur.getRoom(salon)?.getMember(destinataire.getUserId())?.membership === "join",
  20000, "entrée du destinataire");
await attendre(() => expediteur.getCrypto().isEncryptionEnabledInRoom(salon), 20000, "chiffrement du salon");

// 2. Message secret, différent à chaque exécution.
const phrase = `Note confidentielle n°${randomBytes(6).toString("hex")} : réunion budgétaire jeudi`;
const { event_id } = await expediteur.sendTextMessage(salon, phrase);

// 3. Le destinataire le reçoit et le déchiffre sur SON appareil.
const evenement = await attendre(() => {
  const ev = destinataire.getRoom(salon)?.findEventById(event_id);
  return ev && !ev.isDecryptionFailure() && ev.getContent()?.body ? ev : null;
}, 60000, "déchiffrement par le destinataire");

console.log("RESULTAT " + JSON.stringify({
  phrase,
  event_id,
  type_sur_le_serveur: evenement.getWireType(),
  algorithme: evenement.getWireContent().algorithm,
  dechiffre_par_destinataire: evenement.getContent().body,
}));

expediteur.stopClient();
destinataire.stopClient();
process.exit(0);
