// firebase.js
const admin = require("firebase-admin");
const serviceAccount = require("/etc/secrets/firebase-service-account.json"); // Download this from Firebase Console

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

module.exports = admin;
