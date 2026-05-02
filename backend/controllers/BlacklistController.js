/**
 * controllers/BlacklistController.js
 *
 * Pattern: MVC — Controller
 * ─────────────────────────
 * รับ HTTP request → เรียก FirewallService → ส่ง HTTP response
 */

"use strict";

class BlacklistController {
  /**
   * @param {import("../services/FirewallService")} firewallService
   */
  constructor(firewallService) {
    this.#firewallService = firewallService;

    this.getAll = this.getAll.bind(this);
    this.add    = this.add.bind(this);
    this.remove = this.remove.bind(this);
  }

  #firewallService;

  /**
   * GET /api/blacklist
   */
  getAll(req, res) {
    const rows = this.#firewallService.getBlacklist();
    res.json(rows);
  }

  /**
   * POST /api/blacklist
   * body: { ip: string, note?: string }
   */
  add(req, res) {
    const { ip, note } = req.body ?? {};

    if (!ip) {
      return res.status(400).json({ error: '"ip" is required' });
    }

    try {
      const created = this.#firewallService.addToBlacklist(ip, note ?? null);
      res.status(201).json(created);
    } catch (err) {
      const status = err.message.includes("already exists") ? 409 : 400;
      res.status(status).json({ error: err.message });
    }
  }

  /**
   * DELETE /api/blacklist/:id
   */
  remove(req, res) {
    const id = Number(req.params.id);

    try {
      this.#firewallService.removeFromBlacklist(id);
      res.json({ ok: true });
    } catch (err) {
      res.status(404).json({ error: err.message });
    }
  }
}

module.exports = BlacklistController;
