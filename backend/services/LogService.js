/**
 * services/LogService.js
 *
 * Pattern: Service Layer
 * ──────────────────────
 * รับผิดชอบ Business Logic ทั้งหมดที่เกี่ยวกับ Event Logs
 * - บันทึก log จาก loader.py
 * - ดึง log ย้อนหลัง
 * - คำนวณ statistics
 * - broadcast log ไปยัง WebSocket clients
 *
 * ไม่รู้จัก HTTP request/response โดยตรง
 */

"use strict";

class LogService {
  /**
   * @param {import("../repositories/LogRepository")} logRepository
   * @param {import("../websocket/WSServer")}          wsServer
   */
  constructor(logRepository, wsServer) {
    this.#logRepo = logRepository;
    this.#ws      = wsServer;
  }

  #logRepo;
  #ws;

  /**
   * บันทึก event log ใหม่และ broadcast ไปยัง browser ทันที
   * เรียกโดย IPCServer เมื่อรับ event จาก loader.py
   *
   * @param {"blacklist"|"ping"|"web"} eventType
   * @param {string}      ip
   * @param {number|null} port
   * @param {string}      timestamp  ISO string จาก loader.py
   */
  recordAndBroadcast(eventType, ip, port, timestamp) {
    // รับ DB id กลับมาเพื่อใช้ dedup ฝั่ง frontend
    const id = this.#logRepo.create(eventType, ip, port ?? null);

    this.#ws.broadcast({
      type:      "log",
      id,                          // ← DB id จริง ใช้ dedup ใน browser
      eventType,
      ip,
      port:      port ?? null,
      timestamp: timestamp ?? new Date().toISOString(),
    });
  }

  /**
   * ดึง log ล่าสุด
   * @param {number} limit  1–1000 (default 200)
   * @returns {Array}
   */
  getRecentLogs(limit = 200) {
    const safeLimit = Math.min(Math.max(Number(limit) || 200, 1), 1000);
    return this.#logRepo.findRecent(safeLimit);
  }

  /**
   * ดึงสถิติสรุป
   * @returns {{ total: number, byType: Array, last24h: number }}
   */
  getStats() {
    return {
      total:   this.#logRepo.countTotal(),
      byType:  this.#logRepo.countByType(),
      last24h: this.#logRepo.countLast24h(),
    };
  }
}

module.exports = LogService;