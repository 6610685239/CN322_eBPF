/**
 * services/FirewallService.js
 *
 * Pattern: Service Layer
 * ──────────────────────
 * รับผิดชอบ Business Logic ทั้งหมดที่เกี่ยวกับ Firewall Rules
 * - toggle feature flags
 * - จัดการ blacklist IP
 * - จัดการ port blocklist
 * - sync กับ BPF kernel ผ่าน IPCServer
 *
 * ไม่รู้จัก HTTP request/response โดยตรง
 */

"use strict";

/** Regex สำหรับ validate IPv4 */
const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;

class FirewallService {
  /**
   * @param {import("../repositories/FeatureFlagRepository")} featureFlagRepository
   * @param {import("../repositories/BlacklistRepository")}   blacklistRepository
   * @param {import("../repositories/PortRepository")}        portRepository
   * @param {import("../ipc/IPCServer")}                      ipcServer
   */
  constructor(featureFlagRepository, blacklistRepository, portRepository, ipcServer) {
    this.#featureRepo  = featureFlagRepository;
    this.#blacklistRepo = blacklistRepository;
    this.#portRepo     = portRepository;
    this.#ipc          = ipcServer;
  }

  #featureRepo;
  #blacklistRepo;
  #portRepo;
  #ipc;

  // ── Feature Flags ─────────────────────────────────────────────────────────

  /**
   * ดึงสถานะ feature flags ทั้งหมด
   * @returns {Record<string, boolean>}
   */
  getFeatures() {
    return this.#featureRepo.findAllAsMap();
  }

  /**
   * เปิด/ปิด feature และ sync ไปยัง BPF kernel ทันที
   * @param {"blacklist"|"ping"|"port"} featureName
   * @param {boolean} enabled
   * @throws {Error} ถ้าชื่อ feature ไม่ถูกต้อง
   */
  toggleFeature(featureName, enabled) {
    const valid = ["blacklist", "ping", "port"];
    if (!valid.includes(featureName)) {
      throw new Error(`Unknown feature: "${featureName}". Valid: ${valid.join(", ")}`);
    }

    this.#featureRepo.setEnabled(featureName, enabled);
    this.#ipc.send({ action: "toggle_feature", feature: featureName, enabled: enabled ? 1 : 0 });

    return { feature: featureName, enabled };
  }

  // ── Blacklist IP ──────────────────────────────────────────────────────────

  /**
   * ดึง blacklist IP ทั้งหมด
   */
  getBlacklist() {
    return this.#blacklistRepo.findAll();
  }

  /**
   * เพิ่ม IP เข้า blacklist และ sync ไปยัง BPF kernel
   * @param {string} ip
   * @param {string|null} note
   * @returns {{ id: number, ip: string, note: string|null }}
   * @throws {Error} ถ้า IP format ผิด หรือ IP ซ้ำ
   */
  addToBlacklist(ip, note = null) {
    if (!IPV4_REGEX.test(ip)) {
      throw new Error(`Invalid IPv4 address: "${ip}"`);
    }

    let id;
    try {
      id = this.#blacklistRepo.create(ip, note);
    } catch (err) {
      if (err.message.includes("UNIQUE")) {
        throw new Error(`IP "${ip}" already exists in blacklist`);
      }
      throw err;
    }

    this.#ipc.send({ action: "add_ip", ip });
    return { id, ip, note };
  }

  /**
   * ลบ IP ออกจาก blacklist และ sync ไปยัง BPF kernel
   * @param {number} id
   * @throws {Error} ถ้าไม่พบ id
   */
  removeFromBlacklist(id) {
    const row = this.#blacklistRepo.findById(id);
    if (!row) throw new Error(`Blacklist entry id=${id} not found`);

    this.#blacklistRepo.deleteById(id);
    this.#ipc.send({ action: "remove_ip", ip: row.ip });
  }

  // ── Port Blocklist ────────────────────────────────────────────────────────

  /**
   * ดึง port blocklist ทั้งหมด
   */
  getPortBlocklist() {
    return this.#portRepo.findAll();
  }

  /**
   * เพิ่ม port เข้า blocklist และ sync ไปยัง BPF kernel
   * @param {number} port
   * @param {string|null} note
   * @returns {{ id: number, port: number, note: string|null }}
   * @throws {Error} ถ้า port range ผิด หรือ port ซ้ำ
   */
  addPort(port, note = null) {
    const portNum = Number(port);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      throw new Error(`Invalid port: "${port}". Must be integer 1–65535`);
    }

    let id;
    try {
      id = this.#portRepo.create(portNum, note);
    } catch (err) {
      if (err.message.includes("UNIQUE")) {
        throw new Error(`Port ${portNum} is already blocked`);
      }
      throw err;
    }

    this.#ipc.send({ action: "add_port", port: portNum });
    return { id, port: portNum, note };
  }

  /**
   * ลบ port ออกจาก blocklist และ sync ไปยัง BPF kernel
   * @param {number} id
   * @throws {Error} ถ้าไม่พบ id
   */
  removePort(id) {
    const row = this.#portRepo.findById(id);
    if (!row) throw new Error(`Port entry id=${id} not found`);

    this.#portRepo.deleteById(id);
    this.#ipc.send({ action: "remove_port", port: row.port });
  }
}

module.exports = FirewallService;
