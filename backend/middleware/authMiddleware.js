/**
 * middleware/authMiddleware.js
 *
 * Express middleware สำหรับตรวจสอบ JWT Token
 * Inject AuthService เพื่อหลีกเลี่ยงการ hardcode secret
 */

"use strict";

/**
 * สร้าง auth middleware โดย inject AuthService
 * @param {import("../services/AuthService")} authService
 * @returns {import("express").RequestHandler}
 */
function createAuthMiddleware(authService) {
  return function authMiddleware(req, res, next) {
    const header = req.headers.authorization ?? "";
    const token  = header.replace(/^Bearer\s+/i, "").trim();

    if (!token) {
      return res.status(401).json({ error: "Authorization token required" });
    }

    try {
      req.user = authService.verifyToken(token);
      next();
    } catch {
      res.status(401).json({ error: "Invalid or expired token" });
    }
  };
}

module.exports = createAuthMiddleware;
