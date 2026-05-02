/**
 * controllers/LogController.js
 *
 * Pattern: MVC — Controller
 * ─────────────────────────
 * รับ HTTP request → เรียก LogService → ส่ง HTTP response
 */

"use strict";

class LogController {
  /**
   * @param {import("../services/LogService")} logService
   */
  constructor(logService) {
    this.#logService = logService;

    this.getLogs  = this.getLogs.bind(this);
    this.getStats = this.getStats.bind(this);
  }

  #logService;

  /**
   * GET /api/logs?limit=200
   */
  getLogs(req, res) {
    const limit = req.query.limit ?? 200;
    const rows  = this.#logService.getRecentLogs(limit);
    res.json(rows);
  }

  /**
   * GET /api/stats
   */
  getStats(req, res) {
    const stats = this.#logService.getStats();
    res.json(stats);
  }
}

module.exports = LogController;
