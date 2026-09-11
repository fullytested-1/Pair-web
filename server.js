import "dotenv/config";
import express from "express";
import mongoose from "mongoose";
import crypto from "node:crypto";
import QRCode from "qrcode";
import pino from "pino";
import * as Baileys from "@whiskeysockets/baileys";
import { fileURLToPath } from "node:url";
import path from "node:path";

const {
  Browsers,
  DisconnectReason,
  makeCacheableSignalKeyStore,
  fetchLatestBaileysVersion
} = Baileys;

// Baileys has shipped different ESM/CJS export shapes across releases.
// Resolve makeWASocket from either the default or named export so the app
// works with the installed package without changing the dependency version.
const makeWASocket =
  typeof Baileys.default === "function"
    ? Baileys.default
    : typeof Baileys.makeWASocket === "function"
      ? Baileys.makeWASocket
      : typeof Baileys.default?.makeWASocket === "function"
        ? Baileys.default.makeWASocket
        : null;

if (typeof makeWASocket !== "function") {
  throw new Error("Unable to load makeWASocket from @whiskeysockets/baileys");
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const PREFIX = process.env.SESSION_PREFIX || "ROMA~";
const ENCRYPTION_KEY_HEX = process.env.SESSION_ENCRYPTION_KEY || "";
const INTERNAL_SECRET = process.env.INTERNAL_SECRET || "";

if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI is required");
if (!/^[0-9a-fA-F]{64}$/.test(ENCRYPTION_KEY_HEX)) {
  throw new Error("SESSION_ENCRYPTION_KEY must contain exactly 64 hexadecimal characters");
}
const ENC_KEY = Buffer.from(ENCRYPTION_KEY_HEX, "hex");

const sessionSchema = new mongoose.Schema({
  sessionId: { type: String, unique: true, index: true },
  status: { type: String, enum: ["connecting","waiting","connected","logged_out","error"], default: "connecting" },
  phoneNumber: String,
  pairingCode: String,
  qr: String,
  userJid: String,
  error: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now, index: true }
}, { collection: "roma_sessions" });

const authSchema = new mongoose.Schema({
  sessionId: { type: String, index: true },
  category: String,
  key: String,
  value: String,
  updatedAt: { type: Date, default: Date.now }
}, { collection: "roma_auth" });
authSchema.index({ sessionId: 1, category: 1, key: 1 }, { unique: true });

const Session = mongoose.model("Session", sessionSchema);
const Auth = mongoose.model("Auth", authSchema);

const sockets = new Map();
const attempts = new Map();

function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(value)), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64url");
}
function decrypt(value) {
  const raw = Buffer.from(value, "base64url");
  const iv = raw.subarray(0, 12), tag = raw.subarray(12, 28), body = raw.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", ENC_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString();
}
function makeSessionId() {
  return PREFIX + crypto.randomBytes(18).toString("base64url").replace(/[-_]/g, "").slice(0, 24);
}
function normalizePhone(countryCode, phoneNumber) {
  const cc = String(countryCode || "").replace(/\D/g, "");
  const num = String(phoneNumber || "").replace(/\D/g, "");
  if (!cc || !num || cc.length > 4 || num.length < 6 || num.length > 15) throw new Error("Invalid country code or phone number");
  return cc + num;
}
function safeJson(value) {
  return JSON.stringify(value, (_, v) => Buffer.isBuffer(v) ? { type: "Buffer", data: [...v] } : v);
}
function reviveJson(text) {
  return JSON.parse(text, (_, v) => v && v.type === "Buffer" && Array.isArray(v.data) ? Buffer.from(v.data) : v);
}
async function saveAuth(sessionId, category, key, value) {
  const encoded = encrypt(safeJson(value));
  await Auth.findOneAndUpdate(
    { sessionId, category, key },
    { $set: { value: encoded, updatedAt: new Date() } },
    { upsert: true, new: true }
  );
}
async function loadAuth(sessionId, category, key) {
  const doc = await Auth.findOne({ sessionId, category, key }).lean();
  return doc ? reviveJson(decrypt(doc.value)) : null;
}
async function removeSession(sessionId) {
  sockets.delete(sessionId);
  await Auth.deleteMany({ sessionId });
  await Session.deleteOne({ sessionId });
}
function publicState(doc) {
  return {
    success: true,
    sessionId: doc.sessionId,
    status: doc.status,
    pairingCode: doc.pairingCode || null,
    qr: doc.qr || null,
    userJid: doc.userJid || null,
    error: doc.error || null
  };
}

function rateLimit(ip) {
  const now = Date.now();
  const current = attempts.get(ip) || { count: 0, at: now };
  if (now - current.at > 60_000) { current.count = 0; current.at = now; }
  current.count++;
  attempts.set(ip, current);
  return current.count <= 8;
}

async function createAuthState(sessionId) {
  const creds = await loadAuth(sessionId, "creds", "creds");
  const state = {
    creds: creds || undefined,
    keys: {
      get: async (type, ids) => {
        const out = {};
        for (const id of ids) out[id] = await loadAuth(sessionId, "key", type + ":" + id);
        return out;
      },
      set: async data => {
        const ops = [];
        for (const [type, values] of Object.entries(data)) {
          for (const [id, value] of Object.entries(values)) {
            ops.push(saveAuth(sessionId, "key", type + ":" + id, value));
          }
        }
        await Promise.all(ops);
      }
    }
  };
  return {
    state,
    saveCreds: async () => saveAuth(sessionId, "creds", "creds", state.creds)
  };
}

async function updateSession(sessionId, patch) {
  await Session.updateOne({ sessionId }, { $set: { ...patch, updatedAt: new Date() } });
}

async function startSocket(sessionId, phoneNumber, mode) {
  const { state, saveCreds } = await createAuthState(sessionId);
  const { version } = await fetchLatestBaileysVersion();
  const sock = makeWASocket({
    version,
    auth: { creds: state.creds, keys: makeCacheableSignalKeyStore(state.keys, pino({ level: "silent" })) },
    printQRInTerminal: false,
    browser: Browsers.ubuntu("Chrome"),
    logger: pino({ level: "silent" }),
    markOnlineOnConnect: false,
    syncFullHistory: false
  });
  sockets.set(sessionId, sock);
  sock.ev.on("creds.update", saveCreds);

  sock.ev.on("connection.update", async update => {
    const { connection, lastDisconnect, qr } = update;
    try {
      if (qr && mode === "qr") {
        const dataUrl = await QRCode.toDataURL(qr, { margin: 1, width: 320 });
        await updateSession(sessionId, { status: "waiting", qr: dataUrl, error: null });
      }
      if (connection === "open") {
        const jid = sock.user?.id || null;
        await updateSession(sessionId, { status: "connected", userJid: jid, qr: null, pairingCode: null, error: null });
        const msg = "ROMA Session ID:\\n" + sessionId;
        if (jid) await sock.sendMessage(jid, { text: msg });
      }
      if (connection === "close") {
        const code = lastDisconnect?.error?.output?.statusCode;
        if (code === DisconnectReason.loggedOut) {
          await removeSession(sessionId);
        } else if (sockets.has(sessionId)) {
          await updateSession(sessionId, { status: "error", error: "WhatsApp connection closed. Reconnect by creating a new session." });
          sockets.delete(sessionId);
        }
      }
    } catch (err) {
      await updateSession(sessionId, { status: "error", error: err?.message || "Connection error" });
    }
  });

  if (mode === "pair") {
    await new Promise(r => setTimeout(r, 1500));
    const code = await sock.requestPairingCode(phoneNumber);
    await updateSession(sessionId, { status: "waiting", pairingCode: code, qr: null });
  } else {
    await updateSession(sessionId, { status: "waiting" });
  }
}

app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/health", async (_req, res) => {
  res.json({ ok: true, service: "roma-pairing-web", mongodb: mongoose.connection.readyState === 1 });
});

app.post("/api/pair", async (req, res) => {
  try {
    if (!rateLimit(req.ip)) return res.status(429).json({ success: false, error: "Too many requests. Try again later." });
    const phone = normalizePhone(req.body.countryCode, req.body.phoneNumber);
    const sessionId = makeSessionId();
    await Session.create({ sessionId, phoneNumber: phone, status: "connecting" });
    startSocket(sessionId, phone, "pair").catch(async err => {
      await updateSession(sessionId, { status: "error", error: err?.message || "Pairing failed" });
    });
    res.json({ success: true, sessionId });
  } catch (err) {
    res.status(400).json({ success: false, error: err?.message || "Invalid request" });
  }
});

app.post("/api/qr", async (req, res) => {
  try {
    if (!rateLimit(req.ip)) return res.status(429).json({ success: false, error: "Too many requests. Try again later." });
    const sessionId = makeSessionId();
    await Session.create({ sessionId, status: "connecting" });
    startSocket(sessionId, null, "qr").catch(async err => {
      await updateSession(sessionId, { status: "error", error: err?.message || "QR failed" });
    });
    res.json({ success: true, sessionId });
  } catch (err) {
    res.status(500).json({ success: false, error: "Unable to create session" });
  }
});

app.get("/api/session/:sessionId", async (req, res) => {
  const id = req.params.sessionId;
  if (!id.startsWith(PREFIX) || id.length > 80) return res.status(404).json({ success: false, error: "Session not found" });
  const doc = await Session.findOne({ sessionId: id }).lean();
  if (!doc) return res.status(404).json({ success: false, error: "Session not found" });
  res.json(publicState(doc));
});

app.delete("/api/session/:sessionId", async (req, res) => {
  if (INTERNAL_SECRET && req.get("x-internal-secret") !== INTERNAL_SECRET) return res.status(401).json({ success: false, error: "Unauthorized" });
  const id = req.params.sessionId;
  if (!id.startsWith(PREFIX)) return res.status(404).json({ success: false });
  const sock = sockets.get(id);
  try { if (sock) await sock.logout(); } catch {}
  await removeSession(id);
  res.json({ success: true });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ success: false, error: "Internal server error" });
});

process.on("unhandledRejection", err => console.error("Unhandled rejection:", err));
process.on("uncaughtException", err => console.error("Uncaught exception:", err));

await mongoose.connect(process.env.MONGODB_URI);
console.log("MongoDB connected");
app.listen(PORT, () => console.log("ROMA Pairing Web listening on port " + PORT));