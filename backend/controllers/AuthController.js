/**
 * controllers/AuthController.js
 *
 * Pattern: MVC — Controller
 * ─────────────────────────
 * รับ HTTP request → validate input → เรียก AuthService → ส่ง HTTP response
 * ไม่มี business logic หรือ SQL อยู่ใน class นี้
 */

"use strict";

class AuthController {
  /**
   * @param {import("../services/AuthService")} authService
   */
  constructor(authService) {
    this.#authService = authService;

    // bind เพื่อให้ใช้ใน express route ได้โดยตรง
    this.login = this.login.bind(this);
  }

  /** @type {import("../services/AuthService")} */
  #authService;

  /**
   * POST /api/login
   * @param {import("express").Request}  req
   * @param {import("express").Response} res
   */
  login(req, res) {
    const { username, password } = req.body ?? {};

    if (!username || !password) {
      return res.status(400).json({ error: "username and password are required" });
    }

    try {
      const result = this.#authService.login(username, password);
      res.json(result);
    } catch {
      res.status(401).json({ error: "Invalid credentials" });
    }
  }
}

module.exports = AuthController;
