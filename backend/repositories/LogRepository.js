/**
 * repositories/LogRepository.js
 *
 * Pattern: Repository
 * ───────────────────
 * รับผิดชอบการเข้าถึงข้อมูล Event Logs ใน database เท่านั้น
 */

"use strict";

class LogRepository {
  /**
   * @param {import("better-sqlite3").Database} db
   */
  constructor(db) {
    this.#db = db;
  }

  /** @type {import("better-sqlite3").Database} */
  #db;

  /**
   * บันทึก log event ใหม่
   * @param {"blacklist"|"ping"|"web"} eventType
   * @param {string} ip
   * @param {number|null} port
   * @returns {number} lastInsertRowid
   */
  create(eventType, ip, port = null) {
    const info = this.#db
      .prepare("INSERT INTO logs (event_type, ip, port) VALUES (?, ?, ?)")
      .run(eventType, ip, port);
    return info.lastInsertRowid;
  }

  /**
   * ดึง log ล่าสุด จำกัดจำนวน
   * @param {number} limit
   * @returns {Array<{ id: number, event_type: string, ip: string, port: number|null, created_at: string }>}
   */
  findRecent(limit = 200) {
    return this.#db
      .prepare(
        `SELECT id, event_type, ip, port, created_at
         FROM logs
         ORDER BY id DESC
         LIMIT ?`
      )
      .all(limit)
      .reverse();
  }

  /**
   * นับ log ทั้งหมด
   * @returns {number}
   */
  countTotal() {
    return this.#db.prepare("SELECT COUNT(*) AS c FROM logs").get().c;
  }

  /**
   * นับ log แยกตาม event_type
   * @returns {Array<{ event_type: string, c: number }>}
   */
  countByType() {
    return this.#db
      .prepare("SELECT event_type, COUNT(*) AS c FROM logs GROUP BY event_type")
      .all();
  }

  /**
   * นับ log ใน 24 ชั่วโมงล่าสุด
   * @returns {number}
   */
  countLast24h() {
    return this.#db
      .prepare(
        `SELECT COUNT(*) AS c FROM logs
         WHERE created_at >= datetime('now', '-24 hours')`
      )
      .get().c;
  }
}

module.exports = LogRepository;
