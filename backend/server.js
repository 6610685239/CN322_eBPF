/**
 * server.js — Entry Point
 * ───────────────────────
 * หน้าที่เดียวของไฟล์นี้คือ "bootstrap" — สร้าง instance ทั้งหมด
 * แล้ว inject dependency ตามลำดับที่ถูกต้อง
 *
 * ไม่มี business logic, SQL, หรือ HTTP handling อยู่ที่นี่
 */

"use strict";

const http    = require("http");
const express = require("express");
const cors    = require("cors");

// ── Config ─────────────────────────────────────────────────────────────────
const PORT          = process.env.PORT          || 3001;
const JWT_SECRET    = process.env.JWT_SECRET    || "change_me_in_production";
const DB_PATH       = process.env.FIREWALL_DB   || "/var/lib/firewall/firewall.db";
const IPC_SOCK_PATH = process.env.IPC_SOCK_PATH || "/tmp/firewall.sock";
const ADMIN_USER    = process.env.ADMIN_USER    || "admin";
const ADMIN_PASS    = process.env.ADMIN_PASS    || "admin1234";

// ── Import all classes ─────────────────────────────────────────────────────
const Database               = require("./config/Database");
const UserRepository         = require("./repositories/UserRepository");
const BlacklistRepository    = require("./repositories/BlacklistRepository");
const PortRepository         = require("./repositories/PortRepository");
const LogRepository          = require("./repositories/LogRepository");
const FeatureFlagRepository  = require("./repositories/FeatureFlagRepository");
const FloodRateRepository    = require("./repositories/FloodRateRepository");

const AuthService            = require("./services/AuthService");
const FirewallService        = require("./services/FirewallService");
const LogService             = require("./services/LogService");
const FloodService           = require("./services/FloodService");

const AuthController         = require("./controllers/AuthController");
const FeatureController      = require("./controllers/FeatureController");
const BlacklistController    = require("./controllers/BlacklistController");
const PortController         = require("./controllers/PortController");
const LogController          = require("./controllers/LogController");
const FloodController        = require("./controllers/FloodController");

const createRouter           = require("./routes/index");
const createAuthMiddleware   = require("./middleware/authMiddleware");
const IPCServer              = require("./ipc/IPCServer");
const WSServer               = require("./websocket/WSServer");

// ══════════════════════════════════════════════════════════════════════════
//  1. Config layer — Singleton Database
// ══════════════════════════════════════════════════════════════════════════
const db = Database.getInstance(DB_PATH).getConnection();

// ══════════════════════════════════════════════════════════════════════════
//  2. Repository layer — inject db connection
// ══════════════════════════════════════════════════════════════════════════
const userRepository        = new UserRepository(db);
const blacklistRepository   = new BlacklistRepository(db);
const portRepository        = new PortRepository(db);
const logRepository         = new LogRepository(db);
const featureFlagRepository = new FeatureFlagRepository(db);
const floodRateRepository   = new FloodRateRepository(db);

// ══════════════════════════════════════════════════════════════════════════
//  3. IPC + WebSocket servers (ต้องสร้างก่อน Service เพราะ Service ต้องใช้)
// ══════════════════════════════════════════════════════════════════════════
const app        = express();
const httpServer = http.createServer(app);

const ipcServer = new IPCServer(IPC_SOCK_PATH);
const wsServer  = new WSServer(httpServer, new AuthService(userRepository, JWT_SECRET));

// ══════════════════════════════════════════════════════════════════════════
//  4. Service layer — inject repositories + ipc/ws
// ══════════════════════════════════════════════════════════════════════════
const authService     = new AuthService(userRepository, JWT_SECRET);
const firewallService = new FirewallService(
  featureFlagRepository,
  blacklistRepository,
  portRepository,
  ipcServer
);
const logService = new LogService(logRepository, wsServer);
const floodService = new FloodService(featureFlagRepository, floodRateRepository, ipcServer);

// Seed default admin user
authService.seedDefaultAdmin(ADMIN_USER, ADMIN_PASS);

// ══════════════════════════════════════════════════════════════════════════
//  5. Wire IPC observers — เชื่อม loader.py events กับ LogService + WSServer
// ══════════════════════════════════════════════════════════════════════════
ipcServer.subscribe((msg) => {
  if (msg.type === "ready") {
    console.log("[App] loader.py is ready");
    wsServer.broadcastFirewallStatus(true);
    return;
  }

  if (msg.type === "disconnected") {
    wsServer.broadcastFirewallStatus(false);
    return;
  }

  if (msg.type === "log") {
    logService.recordAndBroadcast(
      msg.eventType,
      msg.ip,
      msg.port ?? null,
      msg.timestamp
    );
  }
});

// ══════════════════════════════════════════════════════════════════════════
//  5b. Push full init state to every new WS client (survives browser refresh)
// ══════════════════════════════════════════════════════════════════════════
wsServer.onClientConnect((ws) => {
  const recentLogs = logService.getRecentLogs(500).map(r => ({
    id:        r.id,
    eventType: r.event_type,
    ip:        r.ip,
    port:      r.port ?? null,
    timestamp: r.created_at,
  }));

  ws.send(JSON.stringify({
    type:        "init",
    features:    firewallService.getFeatures(),
    floodConfigs:floodService.getAllFloodConfigs(),
    logs:        recentLogs,
    fwOnline:    ipcServer.isLoaderConnected,
  }));
});

// ══════════════════════════════════════════════════════════════════════════
//  6. Controller layer — inject services
// ══════════════════════════════════════════════════════════════════════════
const authController      = new AuthController(authService);
const featureController   = new FeatureController(firewallService, wsServer);
const blacklistController = new BlacklistController(firewallService);
const portController      = new PortController(firewallService);
const logController       = new LogController(logService);
const floodController     = new FloodController(floodService);

// ══════════════════════════════════════════════════════════════════════════
//  7. Express app setup
// ══════════════════════════════════════════════════════════════════════════
app.use(cors({ origin: "*" }));
app.use(express.json());

const authMiddleware = createAuthMiddleware(authService);
const router = createRouter(
  authController,
  featureController,
  blacklistController,
  portController,
  logController,
  floodController,
  authMiddleware
);

app.use("/api", router);

// Firewall status & shutdown — inline routes (need ipcServer directly)
app.get("/api/firewall/status", authMiddleware, (_req, res) => {
  res.json({ connected: ipcServer.isLoaderConnected });
});

app.post("/api/firewall/shutdown", authMiddleware, (_req, res) => {
  ipcServer.send({ action: "shutdown" });
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════
//  8. Start servers
// ══════════════════════════════════════════════════════════════════════════
async function bootstrap() {
  await ipcServer.start();

  httpServer.listen(PORT, () => {
    console.log(`[App] HTTP  → http://0.0.0.0:${PORT}`);
    console.log(`[App] WS    → ws://0.0.0.0:${PORT}/ws`);
    console.log(`[App] IPC   → ${IPC_SOCK_PATH}`);
    console.log(`[App] DB    → ${DB_PATH}`);
  });
}

bootstrap().catch((err) => {
  console.error("[App] Bootstrap failed:", err);
  process.exit(1);
});

// ── Graceful shutdown ──────────────────────────────────────────────────────
function shutdown() {
  console.log("\n[App] Shutting down...");
  wsServer.close();
  ipcServer.stop();
  
  // Force exit after 5 seconds
  const shutdownTimeout = setTimeout(() => {
    console.warn("[App] Forced exit after timeout");
    process.exit(1);
  }, 5000);
  
  httpServer.close(() => {
    clearTimeout(shutdownTimeout);
    console.log("[App] Goodbye");
    process.exit(0);
  });
}

process.on("SIGINT",  shutdown);
process.on("SIGTERM", shutdown);
