/**
 * routes/index.js
 *
 * รับผิดชอบการ mapping URL path → Controller method เท่านั้น
 * ไม่มี logic ใดๆ อยู่ใน file นี้
 */

"use strict";

const express = require("express");

/**
 * สร้าง Express Router พร้อม inject dependencies ทั้งหมด
 *
 * @param {import("../controllers/AuthController")}     authController
 * @param {import("../controllers/FeatureController")}  featureController
 * @param {import("../controllers/BlacklistController")}blacklistController
 * @param {import("../controllers/PortController")}     portController
 * @param {import("../controllers/LogController")}      logController
 * @param {import("../controllers/FloodController")}    floodController
 * @param {import("../middleware/authMiddleware")}       authMiddleware
 * @returns {import("express").Router}
 */
function createRouter(
  authController,
  featureController,
  blacklistController,
  portController,
  logController,
  floodController,
  authMiddleware
) {
  const router = express.Router();

  // ── Public ─────────────────────────────────────────────
  router.post("/login", authController.login);

  // ── Protected (ต้อง login ก่อน) ────────────────────────
  router.use(authMiddleware);

  // Features
  router.get  ("/features",       featureController.getAll);
  router.patch("/features/:name", featureController.toggle);

  // Blacklist
  router.get   ("/blacklist",     blacklistController.getAll);
  router.post  ("/blacklist",     blacklistController.add);
  router.delete("/blacklist/:id", blacklistController.remove);

  // Ports
  router.get   ("/ports",     portController.getAll);
  router.post  ("/ports",     portController.add);
  router.delete("/ports/:id", portController.remove);

  // Flood Configuration & Logs
  router.get   ("/flood/config",              floodController.getFloodConfigs);
  router.get   ("/flood/config/:floodType",   floodController.getFloodConfig);
  router.patch ("/flood/config/:floodType/enabled", floodController.setFloodEnabled);
  router.patch ("/flood/config/:floodType/rates",   floodController.updateFloodRates);
  router.get   ("/flood/logs",                floodController.getFloodLogs);
  router.get   ("/flood/logs/:ip",            floodController.getFloodLogsByIp);

  // Logs & Stats
  router.get("/logs",  logController.getLogs);
  router.get("/stats", logController.getStats);

  return router;
}

module.exports = createRouter;
