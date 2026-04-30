/**
 * services/FloodService.js
 *
 * Pattern: Service
 * ────────────────
 * Business logic สำหรับ flood protection management
 * Interface กลางระหว่าง Repository กับ Controller
 */

"use strict";

class FloodService {
  /**
   * @param {FeatureFlagRepository} featureFlagRepository
   * @param {FloodRateRepository} floodRateRepository
   * @param {import("../ipc/IPCServer")} ipcServer
   */
  constructor(featureFlagRepository, floodRateRepository, ipcServer) {
    this.#featureFlagRepository = featureFlagRepository;
    this.#floodRateRepository = floodRateRepository;
    this.#ipc = ipcServer;
  }

  /** @type {FeatureFlagRepository} */
  #featureFlagRepository;

  /** @type {FloodRateRepository} */
  #floodRateRepository;

  /** @type {import("../ipc/IPCServer")} */
  #ipc;

  /**
   * Get all flood configurations with their enabled status
   * @returns {Array<{flood_type: string, enabled: boolean, soft_limit: number, hard_limit: number}>}
   */
  getAllFloodConfigs() {
    const rates = this.#floodRateRepository.findAll();
    const flags = this.#featureFlagRepository.findAllAsMap();

    return rates.map((rate) => ({
      flood_type: rate.flood_type,
      enabled: flags[rate.flood_type] || false,
      soft_limit: rate.soft_limit,
      hard_limit: rate.hard_limit,
    }));
  }

  /**
   * Get configuration for a specific flood type
   * @param {string} floodType - "udp_flood", "icmp_flood", or "syn_flood"
   * @returns {object|null}
   */
  getFloodConfig(floodType) {
    if (!this.#isValidFloodType(floodType)) {
      throw new Error(`Invalid flood type: ${floodType}`);
    }

    const rate = this.#floodRateRepository.findByType(floodType);
    if (!rate) return null;

    const flags = this.#featureFlagRepository.findAllAsMap();

    return {
      flood_type: rate.flood_type,
      enabled: flags[rate.flood_type] || false,
      soft_limit: rate.soft_limit,
      hard_limit: rate.hard_limit,
    };
  }

  /**
   * Toggle flood protection on/off
   * @param {string} floodType
   * @param {boolean} enabled
   * @returns {boolean} success
   */
  setFloodEnabled(floodType, enabled) {
    if (!this.#isValidFloodType(floodType)) {
      throw new Error(`Invalid flood type: ${floodType}`);
    }

    // First ensure the feature flag exists
    const existingFlags = this.#featureFlagRepository.findAllAsMap();
    if (!(floodType in existingFlags)) {
      // Add the feature flag entry manually if needed
      // For now assume it exists via seed() in FeatureFlagRepository
    }

    const result = this.#featureFlagRepository.setEnabled(floodType, enabled);
    this.#ipc.send({ action: "toggle_feature", feature: floodType, enabled: enabled ? 1 : 0 });
    return result;
  }

  /**
   * Update rate limits for a flood type
   * @param {string} floodType
   * @param {number} softLimit
   * @param {number} hardLimit
   * @returns {boolean} success
   */
  updateFloodRates(floodType, softLimit, hardLimit) {
    if (!this.#isValidFloodType(floodType)) {
      throw new Error(`Invalid flood type: ${floodType}`);
    }

    if (softLimit <= 0 || hardLimit <= 0) {
      throw new Error("Limits must be positive numbers");
    }

    if (softLimit >= hardLimit) {
      throw new Error("Soft limit must be less than hard limit");
    }

    const result = this.#floodRateRepository.update(floodType, softLimit, hardLimit);
    this.#ipc.send({ action: "update_flood_rates", flood_type: floodType, soft_limit: softLimit, hard_limit: hardLimit });
    return result;
  }

  /**
   * Get recent flood logs
   * @param {number} limit
   * @returns {Array}
   */
  getRecentLogs(limit = 100) {
    return this.#floodRateRepository.getLogs(limit);
  }

  /**
   * Get logs for a specific IP
   * @param {string} ip
   * @param {number} limit
   * @returns {Array}
   */
  getLogsByIp(ip, limit = 50) {
    return this.#floodRateRepository.getLogsByIp(ip, limit);
  }

  /**
   * Manually add a flood log entry
   * @param {string} floodType
   * @param {string} ip
   * @param {string} event - "soft_limit_hit", "hard_limit_hit", "unblocked"
   * @returns {number} log id
   */
  addFloodLog(floodType, ip, event) {
    if (!this.#isValidFloodType(floodType)) {
      throw new Error(`Invalid flood type: ${floodType}`);
    }

    const validEvents = ["soft_limit_hit", "hard_limit_hit", "unblocked"];
    if (!validEvents.includes(event)) {
      throw new Error(
        `Invalid event: ${event}. Must be one of: ${validEvents.join(", ")}`
      );
    }

    return this.#floodRateRepository.addLog(floodType, ip, event);
  }

  /** @private */
  #isValidFloodType(floodType) {
    return FloodService.VALID_FLOOD_TYPES.includes(floodType);
  }

  static VALID_FLOOD_TYPES = ["udp_flood", "icmp_flood", "syn_flood"];
}

module.exports = FloodService;
