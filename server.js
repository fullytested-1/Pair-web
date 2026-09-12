import "dotenv/config";
import express from "express";
import mongoose from "mongoose";
import crypto from "node:crypto";
import QRCode from "qrcode";
import pino from "pino";
import * as Baileys from "@whiskeysockets/baileys";
import path from "node:path";
import { fileURLToPath } from "node:url";

const {
  Browsers,
  DisconnectReason,
  makeCacheableSignalKeyStore,
  fetchLatestWaWebVersion,
  initAuthCreds
} = Baileys;

const makeWASocket =
  typeof Baileys.default === "function"
    ? Baileys.default
    : typeof Baileys.makeWASocket === "function"
      ? Baileys.makeWASocket
      : typeof Baileys.default?.makeWASocket === "function"
        ? Baileys.default.makeWASocket
        : null;

if (!makeWASocket) {
  throw new Error("Unable to load makeWASocket from @whiskeysockets/baileys");
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const PREFIX = process.env.SESSION_PREFIX || "ROMA~";
const ENC_HEX = process.env.SESSION_ENCRYPTION_KEY || "";
const INTERNAL_SECRET = process.env.INTERNAL_SECRET || "";

if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI is required");
if (!/^[0-9a-fA-F]{64}$/.test(ENC_HEX)) {
  throw new Error("SESSION_ENCRYPTION_KEY must be exactly 64 hexadecimal characters");
}
const ENC_KEY = Buffer.from(ENC_HEX, "hex");

const sessionSchema = new mongoose.Schema({
  sessionId: { type: String, unique: true, index: true },
  status: {
    type: String,
    enum: ["connecting", "waiting", "connected", "logged_out", "error"],
    default: "connecting"
  },
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

const botMessageSchema = new mongoose.Schema({
  sessionId: { type: String, index: true },
  messageId: { type: String, index: true },
  from: String,
  text: String,
  createdAt: { type: Date, default: Date.now, index: true }
}, { collection: "roma_bot_messages" });
botMessageSchema.index({ sessionId: 1, createdAt: 1 });
const BotMessage = mongoose.model("BotMessage", botMessageSchema);

function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const body = Buffer.concat([cipher.update(Buffer.from(value)), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64url");
}

function decrypt(value) {
  const raw = Buffer.from(value, "base64url");
  if (raw.length < 29) throw new Error("Invalid encrypted auth value");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const body = raw.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", ENC_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString();
}

function safeJson(value) {
  return JSON.stringify(value, (_, v) =>
    Buffer.isBuffer(v) ? { type: "Buffer", data: [...v] } : v
  );
}

function reviveJson(value) {
  return JSON.parse(value, (_, v) =>
    v && v.type === "Buffer" && Array.isArray(v.data)
      ? Buffer.from(v.data)
      : v
  );
}

async function saveAuth(sessionId, category, key, value) {
  await Auth.findOneAndUpdate(
    { sessionId, category, key },
    { $set: { value: encrypt(safeJson(value)), updatedAt: new Date() } },
    { upsert: true, new: true }
  );
}

async function loadAuth(sessionId, category, key) {
  const doc = await Auth.findOne({ sessionId, category, key }).lean();
  return doc ? reviveJson(decrypt(doc.value)) : null;
}

async function updateSession(sessionId, patch) {
  await Session.updateOne(
    { sessionId },
    { $set: { ...patch, updatedAt: new Date() } }
  );
}

async function deleteSession(sessionId) {
  sockets.delete(sessionId);
  await Auth.deleteMany({ sessionId });
  await Session.deleteOne({ sessionId });
}

function makeSessionId() {
  return PREFIX + crypto.randomBytes(18).toString("base64url").replace(/[-_]/g, "").slice(0, 24);
}

function normalizePhone(countryCode, phoneNumber) {
  const cc = String(countryCode ?? "").replace(/\D/g, "");
  const number = String(phoneNumber ?? "").replace(/\D/g, "");

  if (!cc || !number || cc.length > 4 || number.length < 6 || number.length > 15) {
    throw new Error("Invalid country code or phone number");
  }
  return cc + number;
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
  const item = attempts.get(ip) || { count: 0, at: now };

  if (now - item.at >= 60_000) {
    item.count = 0;
    item.at = now;
  }

  item.count++;
  attempts.set(ip, item);
  return item.count <= 8;
}

async function createAuthState(sessionId) {
  const storedCreds = await loadAuth(sessionId, "creds", "creds");

  const state = {
    creds: storedCreds || initAuthCreds(),
    keys: {
      get: async (type, ids) => {
        const result = {};
        for (const id of ids) {
          result[id] = await loadAuth(sessionId, "key", type + ":" + id);
        }
        return result;
      },

      set: async data => {
        const writes = [];

        for (const [type, values] of Object.entries(data)) {
          for (const [id, value] of Object.entries(values)) {
            writes.push(saveAuth(sessionId, "key", type + ":" + id, value));
          }
        }

        await Promise.all(writes);
      }
    }
  };

  return {
    state,
    saveCreds: () => saveAuth(sessionId, "creds", "creds", state.creds)
  };
}

async function getWaVersion() {
  try {
    const result = await fetchLatestWaWebVersion();
    if (result?.version) return result.version;
  } catch (err) {
    console.warn("Could not fetch latest WhatsApp Web version:", err?.message || err);
  }
  return undefined;
}

async function startSocket(sessionId, phoneNumber, mode, restartCount = 0) {
  if (!sockets.has(sessionId)) {
    const exists = await Session.exists({ sessionId });
    if (!exists) return;
  }

  const { state, saveCreds } = await createAuthState(sessionId);
  const version = await getWaVersion();

  const options = {
    auth: {
      creds: state.creds,
      keys: makeCacheableSignalKeyStore(
        state.keys,
        pino({ level: "silent" })
      )
    },
    printQRInTerminal: false,
    logger: pino({ level: "silent" }),
    browser: Browsers.macOS("Chrome"),
    connectTimeoutMs: 60_000,
    qrTimeout: 60_000,
    defaultQueryTimeoutMs: 60_000,
    markOnlineOnConnect: false,
    syncFullHistory: false
  };

  if (version) options.version = version;

  const sock = makeWASocket(options);
  sockets.set(sessionId, sock);
  sock.ev.on("creds.update", saveCreds);

  let pairingRequested = false;
  let finished = false;

  sock.ev.on("connection.update", async update => {
    const { connection, qr, lastDisconnect } = update;

    try {
      if (qr && mode === "qr") {
        const dataUrl = await QRCode.toDataURL(qr, {
          margin: 1,
          width: 320
        });

        await updateSession(sessionId, {
          status: "waiting",
          qr: dataUrl,
          error: null
        });
      }

      if (connection === "open") {
        finished = true;

        const userJid = sock.user?.id || null;

        await updateSession(sessionId, {
          status: "connected",
          userJid,
          pairingCode: null,
          qr: null,
          error: null
        });

        console.log("WhatsApp connected:", sessionId, userJid || "");

        // Send ONLY the opaque ROMA session ID to the newly linked WhatsApp.
        // Do not send the pairing code or any other credentials.
        if (userJid) {
          try {
            await sock.sendMessage(userJid, {
              text: "*_you'resession_*\\n\\nKeep this ID private."
            });
            await sock.sendMessage(userJid, {
              text: sessionId
            });
            console.log("Session ID message sent:", sessionId);
          } catch (err) {
            console.error("Session ID message failed:", err?.message || err);
          }
        }

        // IMPORTANT: the pairing web must release its WhatsApp socket after
        // pairing. The ROMA bot will use the encrypted credentials stored in
        // MongoDB. Keeping two sockets connected with the same credentials
        // causes WhatsApp 401 conflict errors.
        try {
          sockets.delete(sessionId);
          if (typeof sock.end === "function") sock.end(undefined);
          else if (sock.ws && typeof sock.ws.close === "function") sock.ws.close();
        } catch (err) {
          console.warn("Could not close pairing socket:", err?.message || err);
        }
      }

      if (connection === "close") {
        const code = lastDisconnect?.error?.output?.statusCode;
        const message =
          lastDisconnect?.error?.output?.payload?.message ||
          lastDisconnect?.error?.message ||
          "WhatsApp connection closed";

        console.error("WhatsApp connection closed:", {
          sessionId,
          code,
          message
        });

        sockets.delete(sessionId);

        if (code === DisconnectReason.loggedOut) {
          await updateSession(sessionId, {
            status: "logged_out",
            pairingCode: null,
            qr: null,
            error: "WhatsApp logged out this session."
          });
          await Auth.deleteMany({ sessionId });
          return;
        }

        const restartable =
          code === DisconnectReason.restartRequired ||
          code === 515 ||
          code === 503 ||
          code === 408;

        if (restartable && restartCount < 3 && !finished) {
          const waitMs = 2000 * (restartCount + 1);

          await updateSession(sessionId, {
            status: "connecting",
            error: `Temporary WhatsApp connection error (code ${code || "unknown"}). Retrying...`
          });

          setTimeout(() => {
            startSocket(
              sessionId,
              phoneNumber,
              mode,
              restartCount + 1
            ).catch(err => {
              updateSession(sessionId, {
                status: "error",
                error: err?.message || "Reconnect failed"
              }).catch(() => {});
            });
          }, waitMs);

          return;
        }

        if (restartable && finished) {
          await updateSession(sessionId, {
            status: "connected",
            error: null
          });
          return;
        }

        await updateSession(sessionId, {
          status: "error",
          pairingCode: null,
          qr: null,
          error: `${message}${code ? ` (code ${code})` : ""}`
        });
      }
    } catch (err) {
      console.error("connection.update handler error:", err);
      await updateSession(sessionId, {
        status: "error",
        error: err?.message || "Connection update failed"
      });
    }
  });

  sock.ev.on("messages.upsert", async ({ messages }) => {
    for (const msg of messages || []) {
      if (!msg?.message || msg.key?.fromMe) continue;
      const text =
        msg.message.conversation ||
        msg.message.extendedTextMessage?.text ||
        msg.message.imageMessage?.caption ||
        msg.message.videoMessage?.caption ||
        "";
      if (!text.trim()) continue;
      try {
        await BotMessage.findOneAndUpdate(
          { sessionId, messageId: msg.key.id },
          { $setOnInsert: { sessionId, messageId: msg.key.id, from: msg.key.remoteJid, text: text.trim(), createdAt: new Date() } },
          { upsert: true }
        );
      } catch (err) {
        console.error("Bot message store failed:", err?.message || err);
      }
    }
  });

  if (mode === "pair" && !state.creds.registered) {
    // Request the code exactly once for this socket.
    // Do not call requestPairingCode twice.
    await new Promise(resolve => setTimeout(resolve, 1500));

    if (sock.ws?.readyState === 3) {
      throw new Error("WhatsApp socket closed before pairing-code request");
    }

    if (!pairingRequested) {
      pairingRequested = true;

      const code = await sock.requestPairingCode(phoneNumber);

      await updateSession(sessionId, {
        status: "waiting",
        pairingCode: code,
        qr: null,
        error: null
      });

      console.log("Pairing code created for session:", sessionId);
    }
  } else if (mode === "qr") {
    await updateSession(sessionId, {
      status: "waiting",
      error: null
    });
  }
}

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-internal-secret");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "roma-pairing-web",
    mongodb: mongoose.connection.readyState === 1
  });
});

app.post("/api/pair", async (req, res) => {
  try {
    if (!rateLimit(req.ip)) {
      return res.status(429).json({
        success: false,
        error: "Too many requests. Try again later."
      });
    }

    const phone = normalizePhone(
      req.body?.countryCode,
      req.body?.phoneNumber
    );

    const sessionId = makeSessionId();

    await Session.create({
      sessionId,
      phoneNumber: phone,
      status: "connecting"
    });

    startSocket(sessionId, phone, "pair").catch(err => {
      console.error("Pairing start failed:", err);
      updateSession(sessionId, {
        status: "error",
        error: err?.message || "Pairing failed"
      }).catch(() => {});
    });

    res.json({
      success: true,
      sessionId
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      error: err?.message || "Invalid request"
    });
  }
});

app.post("/api/qr", async (req, res) => {
  try {
    if (!rateLimit(req.ip)) {
      return res.status(429).json({
        success: false,
        error: "Too many requests. Try again later."
      });
    }

    const sessionId = makeSessionId();

    await Session.create({
      sessionId,
      status: "connecting"
    });

    startSocket(sessionId, null, "qr").catch(err => {
      console.error("QR start failed:", err);
      updateSession(sessionId, {
        status: "error",
        error: err?.message || "QR failed"
      }).catch(() => {});
    });

    res.json({
      success: true,
      sessionId
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: "Unable to create session"
    });
  }
});

async function readSession(req, res) {
  try {
    const id = req.params.sessionId;

    if (!id.startsWith(PREFIX) || id.length > 80) {
      return res.status(404).json({
        success: false,
        error: "Session not found"
      });
    }

    const doc = await Session.findOne({ sessionId: id }).lean();

    if (!doc) {
      return res.status(404).json({
        success: false,
        error: "Session not found"
      });
    }

    res.json(publicState(doc));
  } catch (err) {
    res.status(500).json({
      success: false,
      error: "Unable to read session"
    });
  }
}

app.get("/api/session/:sessionId", readSession);
app.get("/api/status/:sessionId", readSession);
app.get("/api/bot/messages/:sessionId", async (req, res) => {
  try {
    const id = req.params.sessionId;
    if (!id.startsWith(PREFIX)) return res.status(404).json({ success: false });
    const after = Number(req.query.after || 0);
    const docs = await BotMessage.find({ sessionId: id }).sort({ createdAt: 1 }).limit(100).lean();
    const messages = docs.map((x, i) => ({ id: x.messageId, from: x.from, text: x.text, createdAt: x.createdAt, cursor: i + 1 }));
    const filtered = after ? messages.filter(x => x.cursor > after) : messages;
    res.json({ success: true, messages: filtered, cursor: messages.length ? messages[messages.length - 1].cursor : after });
  } catch (err) {
    res.status(500).json({ success: false, error: "Unable to read bot messages" });
  }
});

app.post("/api/bot/send/:sessionId", async (req, res) => {
  try {
    const id = req.params.sessionId;
    if (!id.startsWith(PREFIX)) return res.status(404).json({ success: false });
    const to = String(req.body?.to || "");
    const text = String(req.body?.text || "");
    if (!to || !text) return res.status(400).json({ success: false, error: "to and text are required" });
    const sock = sockets.get(id);
    if (!sock) return res.status(409).json({ success: false, error: "Session is not connected" });
    await sock.sendMessage(to, { text });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || "Send failed" });
  }
});

app.post("/api/bot/send-video/:sessionId", async (req, res) => {
  try {
    const id = req.params.sessionId;
    const to = String(req.body?.to || "");
    const url = String(req.body?.url || "");
    const caption = String(req.body?.caption || "");
    if (!id.startsWith(PREFIX) || !to || !url) return res.status(400).json({ success: false, error: "Invalid request" });
    const sock = sockets.get(id);
    if (!sock) return res.status(409).json({ success: false, error: "Session is not connected" });
    await sock.sendMessage(to, { video: { url }, caption });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || "Send failed" });
  }
});

app.post("/api/bot/send-image/:sessionId", async (req, res) => {
  try {
    const id = req.params.sessionId;
    const to = String(req.body?.to || "");
    const url = String(req.body?.url || "");
    const caption = String(req.body?.caption || "");
    if (!id.startsWith(PREFIX) || !to || !url) return res.status(400).json({ success: false, error: "Invalid request" });
    const sock = sockets.get(id);
    if (!sock) return res.status(409).json({ success: false, error: "Session is not connected" });
    await sock.sendMessage(to, { image: { url }, caption });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || "Send failed" });
  }
});



app.delete("/api/session/:sessionId", async (req, res) => {
  try {
    if (
      INTERNAL_SECRET &&
      req.get("x-internal-secret") !== INTERNAL_SECRET
    ) {
      return res.status(401).json({
        success: false,
        error: "Unauthorized"
      });
    }

    const id = req.params.sessionId;

    if (!id.startsWith(PREFIX)) {
      return res.status(404).json({ success: false });
    }

    const sock = sockets.get(id);

    try {
      if (sock) await sock.logout();
    } catch {}

    await deleteSession(id);

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: "Unable to delete session"
    });
  }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({
    success: false,
    error: "Internal server error"
  });
});

process.on("unhandledRejection", err => {
  console.error("Unhandled rejection:", err);
});

process.on("uncaughtException", err => {
  console.error("Uncaught exception:", err);
});

await mongoose.connect(process.env.MONGODB_URI);
console.log("MongoDB connected");

app.listen(PORT, "0.0.0.0", () => {
  console.log("ROMA Pairing Web listening on port " + PORT);
});
