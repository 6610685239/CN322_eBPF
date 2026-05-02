/**
 * controllers/PortController.js
 *
 * Pattern: MVC — Controller
 * ─────────────────────────
 * รับ HTTP request → เรียก FirewallService → ส่ง HTTP response
 */

"use strict";

class PortController {
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
   * GET /api/ports
   */
  getAll(req, res) {
    const rows = this.#firewallService.getPortBlocklist();
    res.json(rows);
  }

  /**
   * POST /api/ports
   * body: { port: number, note?: string }
   */
  add(req, res) {
    const { port, note } = req.body ?? {};

    if (port === undefined || port === null) {
      return res.status(400).json({ error: '"port" is required' });
    }

    try {
      const created = this.#firewallService.addPort(port, note ?? null);
      res.status(201).json(created);
    } catch (err) {
      const status = err.message.includes("already blocked") ? 409 : 400;
      res.status(status).json({ error: err.message });
    }
  }

  /**
   * DELETE /api/ports/:id
   */
  remove(req, res) {
    const id = Number(req.params.id);

    try {
      this.#firewallService.removePort(id);
      res.json({ ok: true });
    } catch (err) {
      res.status(404).json({ error: err.message });
    }
  }
}

module.exports = PortController;
