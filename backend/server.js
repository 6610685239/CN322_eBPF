/**
 * server.js — Firewall Dashboard Backend
 *
 * • Express REST API  (port 3001)
 * • WebSocket server  (same port, /ws)
 * • Unix IPC server   (/tmp/firewall.sock) ← loader.py connects here
 * • SQLite database   (/var/lib/firewall/firewall.db)
 * • JWT authentication
 */

"use strict";

const express    = require("express");
const http       = require("http");
const net        = require("net");
const fs         = require("fs");
const path       = require("path");
const os         = require("os");
const { WebSocketServer } = require("ws");
const Database   = require("better-sqlite3");
const jwt        = require("jsonwebtoken");
const bcrypt     = require("bcryptjs");
const cors       = require("cors");

// ─── Config ────────────────────────────────────────────────────────────────
const PORT          = process.env.PORT          || 3001;
const JWT_SECRET    = process.env.JWT_SECRET    || "change_me_in_production_please";
const DB_PATH       = process.env.FIREWALL_DB   || "/var/lib/firewall/firewall.db";
const IPC_SOCK_PATH = process.env.IPC_SOCK_PATH || "/tmp/firewall.sock";
const ADMIN_USER    = process.env.ADMIN_USER    || "admin";
const ADMIN_PASS    = process.env.ADMIN_PASS    || "admin1234";

// ─── DB Setup ───────────────────────────────────────────────────────────────
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL
  );

  CREATE TABLE IF NOT EXISTS feature_flags (
    id      TEXT PRIMARY KEY,   -- 'blacklist' | 'ping' | 'port'
    enabled INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS blacklist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT    UNIQUE NOT NULL,
    note       TEXT,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS port_blocklist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    port       INTEGER UNIQUE NOT NULL,
    note       TEXT,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    ip         TEXT,
    port       INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Seed default admin
const existingAdmin = db.prepare("SELECT id FROM users WHERE username = ?").get(ADMIN_USER);
if (!existingAdmin) {
  const hash = bcrypt.hashSync(ADMIN_PASS, 10);
  db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").run(ADMIN_USER, hash);
  console.log(`[DB] Created default admin: ${ADMIN_USER} / ${ADMIN_PASS}`);
}

// Seed default feature flags
const seedFlag = db.prepare(
  "INSERT OR IGNORE INTO feature_flags (id, enabled) VALUES (?, 1)"
);
["blacklist", "ping", "port"].forEach(f => seedFlag.run(f));

// ─── Express App ────────────────────────────────────────────────────────────
const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());

// ── Auth Middleware ─────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token  = header.replace(/^Bearer\s+/i, "");
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  REST Routes
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: "username and password required" });

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
    expiresIn: "12h",
  });
  res.json({ token, username: user.username });
});

// GET /api/features
app.get("/api/features", requireAuth, (req, res) => {
  const rows = db.prepare("SELECT id, enabled FROM feature_flags").all();
  const result = {};
  rows.forEach(r => (result[r.id] = r.enabled === 1));
  res.json(result);
});

// PATCH /api/features/:name
app.patch("/api/features/:name", requireAuth, (req, res) => {
  const { name }    = req.params;
  const { enabled } = req.body;
  if (!["blacklist", "ping", "port"].includes(name))
    return res.status(400).json({ error: "Unknown feature" });

  const val = enabled ? 1 : 0;
  db.prepare("UPDATE feature_flags SET enabled = ? WHERE id = ?").run(val, name);

  ipcSend({ action: "toggle_feature", feature: name, enabled: val });
  broadcastStatus();
  res.json({ ok: true, feature: name, enabled: !!enabled });
});

// GET /api/blacklist
app.get("/api/blacklist", requireAuth, (req, res) => {
  const rows = db.prepare("SELECT * FROM blacklist ORDER BY created_at DESC").all();
  res.json(rows);
});

// POST /api/blacklist
app.post("/api/blacklist", requireAuth, (req, res) => {
  const { ip, note } = req.body || {};
  if (!ip || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip))
    return res.status(400).json({ error: "Invalid IP address" });

  try {
    const stmt = db.prepare("INSERT INTO blacklist (ip, note) VALUES (?, ?)");
    const info  = stmt.run(ip, note || null);
    ipcSend({ action: "add_ip", ip });
    res.status(201).json({ id: info.lastInsertRowid, ip, note: note || null });
  } catch (e) {
    if (e.message.includes("UNIQUE")) return res.status(409).json({ error: "IP already exists" });
    throw e;
  }
});

// DELETE /api/blacklist/:id
app.delete("/api/blacklist/:id", requireAuth, (req, res) => {
  const row = db.prepare("SELECT ip FROM blacklist WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "Not found" });

  db.prepare("DELETE FROM blacklist WHERE id = ?").run(req.params.id);
  ipcSend({ action: "remove_ip", ip: row.ip });
  res.json({ ok: true });
});

// GET /api/ports
app.get("/api/ports", requireAuth, (req, res) => {
  const rows = db.prepare("SELECT * FROM port_blocklist ORDER BY port ASC").all();
  res.json(rows);
});

// POST /api/ports
app.post("/api/ports", requireAuth, (req, res) => {
  const { port, note } = req.body || {};
  const portNum = parseInt(port, 10);
  if (isNaN(portNum) || portNum < 1 || portNum > 65535)
    return res.status(400).json({ error: "Invalid port (1–65535)" });

  try {
    const info = db.prepare("INSERT INTO port_blocklist (port, note) VALUES (?, ?)").run(portNum, note || null);
    ipcSend({ action: "add_port", port: portNum });
    res.status(201).json({ id: info.lastInsertRowid, port: portNum, note: note || null });
  } catch (e) {
    if (e.message.includes("UNIQUE")) return res.status(409).json({ error: "Port already blocked" });
    throw e;
  }
});

// DELETE /api/ports/:id
app.delete("/api/ports/:id", requireAuth, (req, res) => {
  const row = db.prepare("SELECT port FROM port_blocklist WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "Not found" });

  db.prepare("DELETE FROM port_blocklist WHERE id = ?").run(req.params.id);
  ipcSend({ action: "remove_port", port: row.port });
  res.json({ ok: true });
});

// GET /api/logs?limit=200
app.get("/api/logs", requireAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "200", 10), 1000);
  const rows  = db
    .prepare("SELECT * FROM logs ORDER BY id DESC LIMIT ?")
    .all(limit)
    .reverse();
  res.json(rows);
});

// GET /api/stats
app.get("/api/stats", requireAuth, (req, res) => {
  const total    = db.prepare("SELECT COUNT(*) as c FROM logs").get().c;
  const byType   = db.prepare(
    "SELECT event_type, COUNT(*) as c FROM logs GROUP BY event_type"
  ).all();
  const last24h  = db.prepare(
    "SELECT COUNT(*) as c FROM logs WHERE created_at >= datetime('now','-24 hours')"
  ).get().c;
  res.json({ total, byType, last24h });
});

// ═══════════════════════════════════════════════════════════════════════════
//  HTTP + WebSocket Server
// ═══════════════════════════════════════════════════════════════════════════
const server = http.createServer(app);
const wss    = new WebSocketServer({ server, path: "/ws" });

const wsClients = new Set();

wss.on("connection", (ws, req) => {
  // Authenticate via ?token=... query param
  const url    = new URL(req.url, `http://localhost`);
  const token  = url.searchParams.get("token");
  try {
    jwt.verify(token, JWT_SECRET);
  } catch {
    ws.close(1008, "Unauthorized");
    return;
  }

  wsClients.add(ws);
  console.log(`[WS] Client connected (${wsClients.size} total)`);

  // Send current state on connect
  const features = db.prepare("SELECT id, enabled FROM feature_flags").all();
  ws.send(JSON.stringify({ type: "state", features }));

  ws.on("close", () => {
    wsClients.delete(ws);
    console.log(`[WS] Client disconnected (${wsClients.size} total)`);
  });
});

function broadcast(payload) {
  const msg = JSON.stringify(payload);
  for (const ws of wsClients) {
    if (ws.readyState === 1 /* OPEN */) ws.send(msg);
  }
}

function broadcastStatus() {
  const features = db.prepare("SELECT id, enabled FROM feature_flags").all();
  broadcast({ type: "state", features });
}

// ═══════════════════════════════════════════════════════════════════════════
//  IPC Unix Socket — loader.py connects here
// ═══════════════════════════════════════════════════════════════════════════
let loaderSocket = null;

function ipcSend(payload) {
  if (!loaderSocket) {
    console.warn("[IPC] loader.py not connected — command dropped:", payload);
    return;
  }
  try {
    loaderSocket.write(JSON.stringify(payload) + "\n");
  } catch (e) {
    console.error("[IPC] Send error:", e.message);
  }
}

// Remove stale socket file
if (fs.existsSync(IPC_SOCK_PATH)) fs.unlinkSync(IPC_SOCK_PATH);

const ipcServer = net.createServer((sock) => {
  console.log("[IPC] loader.py connected");
  loaderSocket = sock;

  let buf = "";
  sock.on("data", (chunk) => {
    buf += chunk.toString();
    let idx;
    while ((idx = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (!line) continue;
      try {
        handleLoaderMessage(JSON.parse(line));
      } catch (e) {
        console.error("[IPC] Parse error:", e.message);
      }
    }
  });

  sock.on("close", () => {
    console.log("[IPC] loader.py disconnected");
    loaderSocket = null;
  });

  sock.on("error", (e) => {
    console.error("[IPC] Socket error:", e.message);
    loaderSocket = null;
  });
});

function handleLoaderMessage(msg) {
  if (msg.type === "ready") {
    console.log("[IPC] loader.py is ready");
    broadcast({ type: "firewall_status", connected: true });
    return;
  }

  if (msg.type === "log") {
    // Persist to DB
    db.prepare(
      "INSERT INTO logs (event_type, ip, port) VALUES (?, ?, ?)"
    ).run(msg.eventType, msg.ip, msg.port || null);

    // Broadcast to all browser WebSocket clients
    broadcast({
      type:      "log",
      eventType: msg.eventType,
      ip:        msg.ip,
      port:      msg.port,
      timestamp: msg.timestamp,
    });
  }
}

ipcServer.listen(IPC_SOCK_PATH, () => {
  console.log(`[IPC] Listening on ${IPC_SOCK_PATH}`);
  // Allow loader.py (running as root) to connect
  try { fs.chmodSync(IPC_SOCK_PATH, "0777"); } catch {}
});

// ─── Start HTTP server ─────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`[HTTP] Listening on http://0.0.0.0:${PORT}`);
  console.log(`[WS]   WebSocket on  ws://0.0.0.0:${PORT}/ws`);
});

// Cleanup on exit
process.on("SIGINT",  () => cleanup());
process.on("SIGTERM", () => cleanup());

function cleanup() {
  try { fs.unlinkSync(IPC_SOCK_PATH); } catch {}
  process.exit(0);
}
