"use strict";

const BetterSqlite3 = require("better-sqlite3");
const fs            = require("fs");
const path          = require("path");

class Database {
  /** @type {Database|null} */
  static #instance = null;

  /** @type {import("better-sqlite3").Database} */
  #db = null;

  /**
   * Private constructor — ห้ามเรียก new Database() โดยตรง
   * ให้ใช้ Database.getInstance() เท่านั้น
   * @param {string} dbPath
   */
  constructor(dbPath) {
    if (Database.#instance) {
      throw new Error("Use Database.getInstance() instead of new Database()");
    }
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    this.#db = new BetterSqlite3(dbPath);
    this.#db.pragma("journal_mode = WAL");
    this.#migrate();
  }

  /**
   * ดึง Singleton instance
   * @param {string} [dbPath]
   * @returns {Database}
   */
  static getInstance(dbPath) {
    if (!Database.#instance) {
      if (!dbPath) throw new Error("dbPath required on first call");
      Database.#instance = new Database(dbPath);
    }
    return Database.#instance;
  }

  /**
   * ดึง raw BetterSqlite3 connection (ใช้ใน Repository เท่านั้น)
   * @returns {import("better-sqlite3").Database}
   */
  getConnection() {
    return this.#db;
  }

  /** สร้างตารางถ้ายังไม่มี (Migration) */
  #migrate() {
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT    UNIQUE NOT NULL,
        password_hash TEXT    NOT NULL
      );

      CREATE TABLE IF NOT EXISTS feature_flags (
        id      TEXT    PRIMARY KEY,
        enabled INTEGER NOT NULL DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS blacklist (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ip         TEXT    UNIQUE NOT NULL,
        note       TEXT,
        created_at TEXT    NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS port_blocklist (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        port       INTEGER UNIQUE NOT NULL,
        note       TEXT,
        created_at TEXT    NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS logs (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT    NOT NULL,
        ip         TEXT,
        port       INTEGER,
        created_at TEXT    NOT NULL DEFAULT (datetime('now'))
      );
    `);
  }
}

module.exports = Database;
