/**
 * services/AuthService.js
 *
 * Pattern: Service Layer
 * ──────────────────────
 * รับผิดชอบ Business Logic ทั้งหมดที่เกี่ยวกับ Authentication
 * - ตรวจสอบ credential
 * - ออก JWT Token
 * - seed default admin
 *
 * ไม่รู้จัก HTTP request/response โดยตรง
 */

"use strict";

const bcrypt = require("bcryptjs");
const jwt    = require("jsonwebtoken");

class AuthService {
  /**
   * @param {import("../repositories/UserRepository")} userRepository
   * @param {string} jwtSecret
   * @param {string} jwtExpiresIn
   */
  constructor(userRepository, jwtSecret, jwtExpiresIn = "12h") {
    this.#userRepo    = userRepository;
    this.#jwtSecret   = jwtSecret;
    this.#jwtExpiresIn = jwtExpiresIn;
  }

  /** @type {import("../repositories/UserRepository")} */
  #userRepo;
  #jwtSecret;
  #jwtExpiresIn;

  /**
   * Seed ข้อมูล admin เริ่มต้น (เรียกตอน bootstrap)
   * @param {string} username
   * @param {string} plainPassword
   */
  seedDefaultAdmin(username, plainPassword) {
    if (this.#userRepo.existsByUsername(username)) return;
    const hash = bcrypt.hashSync(plainPassword, 10);
    this.#userRepo.create(username, hash);
    console.log(`[AuthService] Created default admin: ${username}`);
  }

  /**
   * ตรวจสอบ credential และคืน JWT token
   * @param {string} username
   * @param {string} plainPassword
   * @returns {{ token: string, username: string }}
   * @throws {Error} ถ้า credential ผิด
   */
  login(username, plainPassword) {
    const user = this.#userRepo.findByUsername(username);

    if (!user || !bcrypt.compareSync(plainPassword, user.password_hash)) {
      throw new Error("Invalid credentials");
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      this.#jwtSecret,
      { expiresIn: this.#jwtExpiresIn }
    );

    return { token, username: user.username };
  }

  /**
   * ตรวจสอบและ decode JWT token
   * @param {string} token
   * @returns {{ id: number, username: string }}
   * @throws {Error} ถ้า token ไม่ถูกต้อง
   */
  verifyToken(token) {
    return jwt.verify(token, this.#jwtSecret);
  }
}

module.exports = AuthService;
