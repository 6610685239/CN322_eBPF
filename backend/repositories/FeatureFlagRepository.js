/**
 * repositories/FeatureFlagRepository.js
 *
 * Pattern: Repository
 * ───────────────────
 * รับผิดชอบการเข้าถึงข้อมูล Feature Flags ใน database เท่านั้น
 */

"use strict";

/** @typedef {"blacklist"|"ping"|"port"|"udp_flood"|"icmp_flood"|"syn_flood"} FeatureName */

class FeatureFlagRepository {
  /**
   * @param {import("better-sqlite3").Database} db
   */
  constructor(db) {
    this.#db = db;
    this.#seed();
  }

  /** @type {import("better-sqlite3").Database} */
  #db;

  /** @type {FeatureName[]} */
  static VALID_FEATURES = ["blacklist", "ping", "port", "udp_flood", "icmp_flood", "syn_flood"];

  /** เพิ่ม row เริ่มต้นถ้ายังไม่มี */
  #seed() {
    const insert = this.#db.prepare(
      "INSERT OR IGNORE INTO feature_flags (id, enabled) VALUES (?, 1)"
    );
    FeatureFlagRepository.VALID_FEATURES.forEach((f) => insert.run(f));
  }

  /**
   * ดึง feature flags ทั้งหมด
   * @returns {Array<{ id: string, enabled: number }>}
   */
  findAll() {
    return this.#db.prepare("SELECT id, enabled FROM feature_flags").all();
  }

  /**
   * ดึงเป็น object { blacklist: bool, ping: bool, port: bool }
   * @returns {Record<FeatureName, boolean>}
   */
  findAllAsMap() {
    const rows = this.findAll();
    return Object.fromEntries(rows.map((r) => [r.id, r.enabled === 1]));
  }

  /**
   * อัปเดตสถานะ feature
   * @param {FeatureName} name
   * @param {boolean} enabled
   * @returns {boolean} true ถ้าอัปเดตสำเร็จ
   */
  setEnabled(name, enabled) {
    const info = this.#db
      .prepare("UPDATE feature_flags SET enabled = ? WHERE id = ?")
      .run(enabled ? 1 : 0, name);
    return info.changes > 0;
  }
}

module.exports = FeatureFlagRepository;
