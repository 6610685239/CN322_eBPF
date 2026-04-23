/**
 * websocket/WSServer.js
 *
 * Pattern: Observer
 * ─────────────────
 * Subject: WSServer
 * Observers: WebSocket clients (browser tabs)
 *
 * WSServer เก็บ list ของ client ที่ connect อยู่
 * เมื่อมี event ใหม่จาก firewall → broadcast ไปทุก observer
 */

"use strict";

const { WebSocketServer } = require("ws");

class WSServer {
  /**
   * @param {import("http").Server}              httpServer
   * @param {import("../services/AuthService")}  authService
   */
  constructor(httpServer, authService) {
    this.#authService = authService;
    this.#clients     = new Set();
    this.#wss         = new WebSocketServer({ server: httpServer, path: "/ws" });
    this.#init();
  }

  #authService;
  /** @type {Set<import("ws").WebSocket>} */
  #clients;
  /** @type {WebSocketServer} */
  #wss;

  /** ตั้งค่า event handlers สำหรับ WebSocket server */
  #init() {
    this.#wss.on("connection", (ws, req) => {
      // Authenticate ผ่าน query param ?token=...
      const url   = new URL(req.url, "http://localhost");
      const token = url.searchParams.get("token");

      try {
        this.#authService.verifyToken(token);
      } catch {
        ws.close(1008, "Unauthorized");
        return;
      }

      this.#clients.add(ws);
      console.log(`[WSServer] Client connected  (total: ${this.#clients.size})`);

      ws.on("close", () => {
        this.#clients.delete(ws);
        console.log(`[WSServer] Client disconnected (total: ${this.#clients.size})`);
      });

      ws.on("error", (err) => {
        console.error("[WSServer] Client error:", err.message);
        this.#clients.delete(ws);
      });
    });
  }

  /**
   * Broadcast payload ไปยัง observer ทุกตัวที่ connect อยู่
   * @param {object} payload
   */
  broadcast(payload) {
    const msg = JSON.stringify(payload);
    for (const ws of this.#clients) {
      if (ws.readyState === ws.OPEN) {
        ws.send(msg);
      }
    }
  }

  /**
   * Broadcast สถานะ feature flags ปัจจุบัน
   * เรียกหลัง toggle เพื่อ sync UI ทุกหน้าต่าง
   * @param {Record<string, boolean>} featuresMap
   */
  broadcastFeatureState(featuresMap) {
    this.broadcast({ type: "state", features: featuresMap });
  }

  /**
   * แจ้ง client ทุกตัวว่า firewall loader online/offline
   * @param {boolean} connected
   */
  broadcastFirewallStatus(connected) {
    this.broadcast({ type: "firewall_status", connected });
  }

  /** จำนวน client ที่ connect อยู่ ณ ขณะนี้ */
  get clientCount() {
    return this.#clients.size;
  }
}

module.exports = WSServer;
