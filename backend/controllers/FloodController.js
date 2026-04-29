/**
 * controllers/FloodController.js
 *
 * Pattern: Controller
 * ──────────────────
 * HTTP request handlers สำหรับ flood protection management
 */

"use strict";

class FloodController {
  /**
   * @param {FloodService} floodService
   */
  constructor(floodService) {
    this.#floodService = floodService;

    this.getFloodConfigs  = this.getFloodConfigs.bind(this);
    this.getFloodConfig   = this.getFloodConfig.bind(this);
    this.setFloodEnabled  = this.setFloodEnabled.bind(this);
    this.updateFloodRates = this.updateFloodRates.bind(this);
    this.getFloodLogs     = this.getFloodLogs.bind(this);
    this.getFloodLogsByIp = this.getFloodLogsByIp.bind(this);
  }

  /** @type {FloodService} */
  #floodService;

  /**
   * GET /api/flood/config
   * ดึง configuration ของทั้งหมดของ flood types
   */
  getFloodConfigs(req, res) {
    try {
      const configs = this.#floodService.getAllFloodConfigs();
      res.json(configs);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }

  /**
   * GET /api/flood/config/:floodType
   * ดึง configuration ของ flood type เดียว
   */
  getFloodConfig(req, res) {
    try {
      const { floodType } = req.params;
      const config = this.#floodService.getFloodConfig(floodType);
      
      if (!config) {
        return res.status(404).json({ error: "Flood type not found" });
      }

      res.json(config);
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }

  /**
   * PATCH /api/flood/config/:floodType/enabled
   * เปิด/ปิด flood protection สำหรับ type เดียว
   * Body: { enabled: boolean }
   */
  setFloodEnabled(req, res) {
    try {
      const { floodType } = req.params;
      const { enabled } = req.body;

      if (typeof enabled !== "boolean") {
        return res.status(400).json({ error: "enabled must be boolean" });
      }

      const success = this.#floodService.setFloodEnabled(floodType, enabled);
      
      if (!success) {
        return res.status(404).json({ error: "Flood type not found" });
      }

      res.json({ message: "Updated", enabled });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }

  /**
   * PATCH /api/flood/config/:floodType/rates
   * อัปเดต soft_limit และ hard_limit
   * Body: { soft_limit: number, hard_limit: number }
   */
  updateFloodRates(req, res) {
    try {
      const { floodType } = req.params;
      const { soft_limit, hard_limit } = req.body;

      if (typeof soft_limit !== "number" || typeof hard_limit !== "number") {
        return res.status(400).json({ 
          error: "soft_limit and hard_limit must be numbers" 
        });
      }

      const success = this.#floodService.updateFloodRates(
        floodType,
        soft_limit,
        hard_limit
      );

      if (!success) {
        return res.status(404).json({ error: "Flood type not found" });
      }

      res.json({ 
        message: "Updated",
        flood_type: floodType,
        soft_limit,
        hard_limit
      });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }

  /**
   * GET /api/flood/logs
   * ดึง recent flood logs
   * Query: ?limit=N (default 100)
   */
  getFloodLogs(req, res) {
    try {
      const limit = parseInt(req.query.limit) || 100;
      const logs = this.#floodService.getRecentLogs(limit);
      res.json(logs);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }

  /**
   * GET /api/flood/logs/:ip
   * ดึง flood logs สำหรับ IP เดียว
   * Query: ?limit=N (default 50)
   */
  getFloodLogsByIp(req, res) {
    try {
      const { ip } = req.params;
      const limit = parseInt(req.query.limit) || 50;
      const logs = this.#floodService.getLogsByIp(ip, limit);
      res.json(logs);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
}

module.exports = FloodController;
