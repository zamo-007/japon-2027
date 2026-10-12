// Japon 2027 : rangement des photos originales dans le Google Drive de l'organisateur.
// À coller dans un projet Google Apps Script (script.google.com), puis Déployer > Application web :
//   Exécuter en tant que : Moi    ·    Qui a accès : Tout le monde
// Chaque envoi, téléchargement ou suppression doit présenter un ticket à usage court délivré par
// le serveur du voyage (fonction « photos »), lui-même accessible seulement avec un code PIN valide.

const API = "https://hsggyjmeurjsiwegqzbo.supabase.co/functions/v1/photos";
const KEY = "sb_publishable_0CiI_uRcS4WqSY3OTsc85w_TieGW2Ce";
const FOLDER_NAME = "Japon 2027 – photos originales";

function folder_() {
  const props = PropertiesService.getScriptProperties();
  const id = props.getProperty("folder");
  if (id) { try { const f = DriveApp.getFolderById(id); if (!f.isTrashed()) return f; } catch (e) {} }
  const f = DriveApp.createFolder(FOLDER_NAME);
  props.setProperty("folder", f.getId());
  return f;
}

function check_(ticket, extra) {
  const r = UrlFetchApp.fetch(API, {
    method: "post", contentType: "application/json", headers: { apikey: KEY },
    payload: JSON.stringify(Object.assign({ action: "drive_check", ticket: String(ticket || "") }, extra || {})),
    muteHttpExceptions: true,
  });
  if (r.getResponseCode() !== 200) throw new Error("ticket refusé");
  return JSON.parse(r.getContentText());
}

function out_(o) {
  return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON);
}

function doPost(e) {
  try {
    const b = JSON.parse(e.postData.contents);
    if (b.action === "ping") return out_({ ok: true, app: "japon-2027" });
    const t = check_(b.ticket);
    if (b.action === "put" && t.kind === "put") {
      const blob = Utilities.newBlob(Utilities.base64Decode(b.data), b.mime || "application/octet-stream", t.name || "photo");
      const file = folder_().createFile(blob);
      check_(b.ticket, { done: file.getId() });
      return out_({ ok: true, id: file.getId() });
    }
    if (b.action === "get" && t.kind === "get") {
      const file = DriveApp.getFileById(t.drive_id);
      const blob = file.getBlob();
      return out_({ ok: true, name: file.getName(), mime: blob.getContentType(), data: Utilities.base64Encode(blob.getBytes()) });
    }
    if (b.action === "del" && t.kind === "del") {
      DriveApp.getFileById(t.drive_id).setTrashed(true);
      return out_({ ok: true });
    }
    return out_({ ok: false, error: "action" });
  } catch (err) {
    return out_({ ok: false, error: String((err && err.message) || err) });
  }
}

function doGet() {
  return out_({ ok: true, app: "japon-2027" });
}

// À lancer une fois depuis l'éditeur (bouton Exécuter) pour accorder l'accès au Drive.
function autoriser() {
  const f = folder_();
  Logger.log("Dossier prêt : " + f.getName() + " — " + f.getUrl());
}
