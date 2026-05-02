/**
 * repositories/UserRepository.js
 *
 * Pattern: Repository
 * ───────────────────
 * รับผิดชอบการเข้าถึงข้อมูล User ใน database เท่านั้น
 * ไม่มี business logic อยู่ใน class นี้
 */

"use strict";

class UserRepository {
  /**
   * @param {import("better-sqlite3").Database} db
   */
  constructor(db) {
    this.#db = db;
  }

  /** @type {import("better-sqlite3").Database} */
  #db;

  /**
   * ค้นหา user จาก username
   * @param {string} username
   * @returns {{ id: number, username: string, password_hash: string } | undefined}
   */
  findByUsername(username) {
    return this.#db
      .prepare("SELECT id, username, password_hash FROM users WHERE username = ?")
      .get(username);
  }

  /**
   * ตรวจว่ามี user อยู่แล้วหรือไม่
   * @param {string} username
   * @returns {boolean}
   */
  existsByUsername(username) {
    const row = this.#db
      .prepare("SELECT 1 FROM users WHERE username = ?")
      .get(username);
    return !!row;
  }

  /**
   * สร้าง user ใหม่
   * @param {string} username
   * @param {string} passwordHash
   * @returns {number} lastInsertRowid
   */
  create(username, passwordHash) {
    const info = this.#db
      .prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
      .run(username, passwordHash);
    return info.lastInsertRowid;
  }
}

module.exports = UserRepository;
