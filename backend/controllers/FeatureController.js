/**
 * controllers/FeatureController.js
 *
 * Pattern: MVC — Controller
 * ─────────────────────────
 * รับ HTTP request → เรียก FirewallService → ส่ง HTTP response
 * พร้อม broadcast สถานะใหม่ผ่าน WebSocket
 */

"use strict";

class FeatureController {
  /**
   * @param {import("../services/FirewallService")} firewallService
   * @param {import("../websocket/WSServer")}        wsServer
   */
  constructor(firewallService, wsServer) {
    this.#firewallService = firewallService;
    this.#ws              = wsServer;

    this.getAll = this.getAll.bind(this);
    this.toggle = this.toggle.bind(this);
  }

  #firewallService;
  #ws;

  /**
   * GET /api/features
   */
  getAll(req, res) {
    const features = this.#firewallService.getFeatures();
    res.json(features);
  }

  /**
   * PATCH /api/features/:name
   * body: { enabled: boolean }
   */
  toggle(req, res) {
    const { name }    = req.params;
    const { enabled } = req.body ?? {};

    if (typeof enabled !== "boolean") {
      return res.status(400).json({ error: '"enabled" must be a boolean' });
    }

    try {
      const result = this.#firewallService.toggleFeature(name, enabled);

      // Broadcast updated state ไปยัง browser ทุกหน้าต่าง
      this.#ws.broadcastFeatureState(this.#firewallService.getFeatures());

      res.json({ ok: true, ...result });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }
}

module.exports = FeatureController;
