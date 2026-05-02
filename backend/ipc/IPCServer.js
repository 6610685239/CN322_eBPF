/**
 * ipc/IPCServer.js
 *
 * Pattern: Observer
 * ─────────────────
 * Subject: IPCServer (รอรับ event จาก loader.py)
 * Observers: LogService (บันทึก + broadcast ทุก log ที่รับมา)
 *
 * IPCServer เปิด Unix Domain Socket รอให้ loader.py connect
 * เมื่อรับ JSON message → แจ้ง observers ที่ลงทะเบียนไว้
 */

"use strict";

const net = require("net");
const fs  = require("fs");

class IPCServer {
  /**
   * @param {string} socketPath  path ของ Unix socket เช่น /tmp/firewall.sock
   */
  constructor(socketPath) {
    this.#socketPath    = socketPath;
    this.#loaderSocket  = null;
    this.#observers     = [];
    this.#server        = null;
  }

  #socketPath;
  /** @type {import("net").Socket|null} */
  #loaderSocket;
  /** @type {Array<(msg: object) => void>} */
  #observers;
  /** @type {import("net").Server|null} */
  #server;

  // ── Observer Pattern ─────────────────────────────────────────────────────

  /**
   * ลงทะเบียน observer function ที่จะถูกเรียกเมื่อรับ message จาก loader.py
   * @param {(msg: object) => void} observerFn
   */
  subscribe(observerFn) {
    this.#observers.push(observerFn);
  }

  /**
   * แจ้ง observers ทั้งหมดเมื่อรับ message ใหม่
   * @param {object} msg
   */
  #notify(msg) {
    for (const fn of this.#observers) {
      try { fn(msg); } catch (err) {
        console.error("[IPCServer] Observer error:", err.message);
      }
    }
  }

  // ── Server Lifecycle ─────────────────────────────────────────────────────

  /**
   * เริ่ม listen Unix socket
   * @returns {Promise<void>}
   */
  start() {
    return new Promise((resolve) => {
      // ลบ socket file เก่าออกก่อน
      if (fs.existsSync(this.#socketPath)) {
        fs.unlinkSync(this.#socketPath);
      }

      this.#server = net.createServer((socket) => this.#handleConnection(socket));

      this.#server.listen(this.#socketPath, () => {
        // Allow loader.py (root) to connect
        try { fs.chmodSync(this.#socketPath, "0777"); } catch {}
        console.log(`[IPCServer] Listening on ${this.#socketPath}`);
        resolve();
      });
    });
  }

  /** หยุด server และ cleanup socket file */
  stop() {
    this.#loaderSocket?.destroy();
    this.#server?.close();
    try { fs.unlinkSync(this.#socketPath); } catch {}
    console.log("[IPCServer] Stopped");
  }

  // ── Connection Handling ──────────────────────────────────────────────────

  /**
   * จัดการ connection ใหม่จาก loader.py
   * @param {import("net").Socket} socket
   */
  #handleConnection(socket) {
    console.log("[IPCServer] loader.py connected");
    this.#loaderSocket = socket;
    this.#notify({ type: "ready" });

    let buffer = "";

    socket.on("data", (chunk) => {
      buffer += chunk.toString();
      let idx;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (!line) continue;
        try {
          this.#notify(JSON.parse(line));
        } catch (err) {
          console.error("[IPCServer] JSON parse error:", err.message);
        }
      }
    });

    socket.on("close", () => {
      console.log("[IPCServer] loader.py disconnected");
      this.#loaderSocket = null;
      this.#notify({ type: "disconnected" });
    });

    socket.on("error", (err) => {
      console.error("[IPCServer] Socket error:", err.message);
      this.#loaderSocket = null;
    });
  }

  // ── Send Command ─────────────────────────────────────────────────────────

  /**
   * ส่ง command ไปยัง loader.py
   * @param {object} payload
   */
  send(payload) {
    if (!this.#loaderSocket) {
      console.warn("[IPCServer] loader.py not connected — command dropped:", payload);
      return;
    }
    try {
      this.#loaderSocket.write(JSON.stringify(payload) + "\n");
    } catch (err) {
      console.error("[IPCServer] Send failed:", err.message);
      this.#loaderSocket = null;
    }
  }

  /** true ถ้า loader.py กำลัง connect อยู่ */
  get isLoaderConnected() {
    return this.#loaderSocket !== null;
  }
}

module.exports = IPCServer;
