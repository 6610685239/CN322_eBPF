/**
 * repositories/BlacklistRepository.js
 *
 * Pattern: Repository
 * ───────────────────
 * รับผิดชอบการเข้าถึงข้อมูล Blacklist IP ใน database เท่านั้น
 */

"use strict";

class BlacklistRepository {
  /**
   * @param {import("better-sqlite3").Database} db
   */
  constructor(db) {
    this.#db = db;
  }

  /** @type {import("better-sqlite3").Database} */
  #db;

  /**
   * ดึง blacklist IP ทั้งหมด เรียงจากใหม่ → เก่า
   * @returns {Array<{ id: number, ip: string, note: string|null, created_at: string }>}
   */
  findAll() {
    return this.#db
      .prepare("SELECT id, ip, note, created_at FROM blacklist ORDER BY created_at DESC")
      .all();
  }

  /**
   * ดึงเฉพาะ ip string ทั้งหมด (ใช้ตอน load BPF map)
   * @returns {string[]}
   */
  findAllIPs() {
    return this.#db
      .prepare("SELECT ip FROM blacklist")
      .all()
      .map((r) => r.ip);
  }

  /**
   * ค้นหาด้วย id
   * @param {number} id
   * @returns {{ id: number, ip: string } | undefined}
   */
  findById(id) {
    return this.#db
      .prepare("SELECT id, ip FROM blacklist WHERE id = ?")
      .get(id);
  }

  /**
   * เพิ่ม IP เข้า blacklist
   * @param {string} ip
   * @param {string|null} note
   * @returns {number} lastInsertRowid
   * @throws {Error} ถ้า IP ซ้ำ
   */
  create(ip, note = null) {
    const info = this.#db
      .prepare("INSERT INTO blacklist (ip, note) VALUES (?, ?)")
      .run(ip, note);
    return info.lastInsertRowid;
  }

  /**
   * ลบ IP ออกจาก blacklist
   * @param {number} id
   * @returns {boolean} true ถ้าลบสำเร็จ
   */
  deleteById(id) {
    const info = this.#db
      .prepare("DELETE FROM blacklist WHERE id = ?")
      .run(id);
    return info.changes > 0;
  }
}

module.exports = BlacklistRepository;
