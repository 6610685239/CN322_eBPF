/**
 * repositories/PortRepository.js
 *
 * Pattern: Repository
 * ───────────────────
 * รับผิดชอบการเข้าถึงข้อมูล Port Blocklist ใน database เท่านั้น
 */

"use strict";

class PortRepository {
  /**
   * @param {import("better-sqlite3").Database} db
   */
  constructor(db) {
    this.#db = db;
  }

  /** @type {import("better-sqlite3").Database} */
  #db;

  /**
   * ดึง port ที่บล็อกทั้งหมด เรียงจากน้อย → มาก
   * @returns {Array<{ id: number, port: number, note: string|null, created_at: string }>}
   */
  findAll() {
    return this.#db
      .prepare("SELECT id, port, note, created_at FROM port_blocklist ORDER BY port ASC")
      .all();
  }

  /**
   * ดึงเฉพาะ port number ทั้งหมด (ใช้ตอน load BPF map)
   * @returns {number[]}
   */
  findAllPorts() {
    return this.#db
      .prepare("SELECT port FROM port_blocklist")
      .all()
      .map((r) => r.port);
  }

  /**
   * ค้นหาด้วย id
   * @param {number} id
   * @returns {{ id: number, port: number } | undefined}
   */
  findById(id) {
    return this.#db
      .prepare("SELECT id, port FROM port_blocklist WHERE id = ?")
      .get(id);
  }

  /**
   * เพิ่ม port เข้า blocklist
   * @param {number} port
   * @param {string|null} note
   * @returns {number} lastInsertRowid
   * @throws {Error} ถ้า port ซ้ำ
   */
  create(port, note = null) {
    const info = this.#db
      .prepare("INSERT INTO port_blocklist (port, note) VALUES (?, ?)")
      .run(port, note);
    return info.lastInsertRowid;
  }

  /**
   * ลบ port ออกจาก blocklist
   * @param {number} id
   * @returns {boolean} true ถ้าลบสำเร็จ
   */
  deleteById(id) {
    const info = this.#db
      .prepare("DELETE FROM port_blocklist WHERE id = ?")
      .run(id);
    return info.changes > 0;
  }
}

module.exports = PortRepository;
