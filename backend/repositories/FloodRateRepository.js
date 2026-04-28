/**
 * repositories/FloodRateRepository.js
 *
 * Pattern: Repository
 * ───────────────────
 * รับผิดชอบการเข้าถึงข้อมูล Flood Rate Limits ใน database เท่านั้น
 */

"use strict";

class FloodRateRepository {
  /**
   * @param {import("better-sqlite3").Database} db
   */
  constructor(db) {
    this.#db = db;
    this.#seed();
  }

  /** @type {import("better-sqlite3").Database} */
  #db;

  /** @type {string[]} */
  static FLOOD_TYPES = ["udp_flood", "icmp_flood", "syn_flood"];

  /** เพิ่ม row เริ่มต้นถ้ายังไม่มี */
  #seed() {
    const defaults = {
      udp_flood: { soft_limit: 100, hard_limit: 200 },
      icmp_flood: { soft_limit: 50, hard_limit: 100 },
      syn_flood: { soft_limit: 200, hard_limit: 400 },
    };

    const insert = this.#db.prepare(
      "INSERT OR IGNORE INTO flood_rates (flood_type, soft_limit, hard_limit) VALUES (?, ?, ?)"
    );

    Object.entries(defaults).forEach(([type, cfg]) => {
      insert.run(type, cfg.soft_limit, cfg.hard_limit);
    });
  }

  /**
   * ดึง flood rate configuration ทั้งหมด
   * @returns {Array<{ id: number, flood_type: string, soft_limit: number, hard_limit: number, updated_at: string }>}
   */
  findAll() {
    return this.#db
      .prepare("SELECT id, flood_type, soft_limit, hard_limit, updated_at FROM flood_rates ORDER BY flood_type")
      .all();
  }

  /**
   * ดึง configuration สำหรับ flood type เดียว
   * @param {string} floodType - "udp_flood", "icmp_flood", หรือ "syn_flood"
   * @returns {object|null}
   */
  findByType(floodType) {
    return this.#db
      .prepare("SELECT * FROM flood_rates WHERE flood_type = ?")
      .get(floodType);
  }

  /**
   * อัปเดต soft_limit และ hard_limit
   * @param {string} floodType
   * @param {number} softLimit
   * @param {number} hardLimit
   * @returns {boolean} true ถ้าอัปเดตสำเร็จ
   */
  update(floodType, softLimit, hardLimit) {
    const info = this.#db
      .prepare(
        "UPDATE flood_rates SET soft_limit = ?, hard_limit = ?, updated_at = datetime('now') WHERE flood_type = ?"
      )
      .run(softLimit, hardLimit, floodType);
    return info.changes > 0;
  }

  /**
   * Add flood log entry
   * @param {string} floodType - "udp_flood", "icmp_flood", or "syn_flood"
   * @param {string} ip - source IP
   * @param {string} event - "soft_limit_hit", "hard_limit_hit", "unblocked"
   * @returns {number} inserted row id
   */
  addLog(floodType, ip, event) {
    const info = this.#db
      .prepare("INSERT INTO flood_logs (flood_type, ip, event) VALUES (?, ?, ?)")
      .run(floodType, ip, event);
    return info.lastInsertRowid;
  }

  /**
   * Get recent flood logs
   * @param {number} limit - default 100
   * @returns {Array<{id: number, flood_type: string, ip: string, event: string, created_at: string}>}
   */
  getLogs(limit = 100) {
    return this.#db
      .prepare("SELECT * FROM flood_logs ORDER BY created_at DESC LIMIT ?")
      .all(limit);
  }

  /**
   * Get flood logs for specific IP
   * @param {string} ip
   * @param {number} limit
   * @returns {Array}
   */
  getLogsByIp(ip, limit = 50) {
    return this.#db
      .prepare("SELECT * FROM flood_logs WHERE ip = ? ORDER BY created_at DESC LIMIT ?")
      .all(ip, limit);
  }
}

module.exports = FloodRateRepository;
