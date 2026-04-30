const BetterSqlite3 = require('better-sqlite3');
const BlacklistRepository = require('../../repositories/BlacklistRepository');
const FeatureFlagRepository = require('../../repositories/FeatureFlagRepository');
const FloodRateRepository = require('../../repositories/FloodRateRepository');

// migration SQL (kept in-sync with config/Database.js)
const MIGRATE_SQL = `
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL
  );

  CREATE TABLE IF NOT EXISTS feature_flags (
    id      TEXT    PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS blacklist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT    UNIQUE NOT NULL,
    note       TEXT,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS port_blocklist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    port       INTEGER UNIQUE NOT NULL,
    note       TEXT,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS flood_rates (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    flood_type TEXT    UNIQUE NOT NULL,
    soft_limit INTEGER NOT NULL,
    hard_limit INTEGER NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS flood_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    flood_type TEXT    NOT NULL,
    ip         TEXT    NOT NULL,
    event      TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT    NOT NULL,
    ip         TEXT,
    port       INTEGER,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`;

describe('Integration: repositories with SQLite', () => {
  let db;

  beforeEach(() => {
    db = new BetterSqlite3(':memory:');
    db.exec(MIGRATE_SQL);
  });

  afterEach(() => {
    try { db.close(); } catch (e) {}
  });

  test('BlacklistRepository create/find/delete lifecycle', () => {
    const repo = new BlacklistRepository(db);
    const id = repo.create('10.0.0.1', 'test');
    expect(typeof id).toBe('number');

    const all = repo.findAll();
    expect(all.length).toBe(1);
    expect(all[0].ip).toBe('10.0.0.1');

    const row = repo.findById(id);
    expect(row).toBeDefined();
    expect(row.ip).toBe('10.0.0.1');

    const deleted = repo.deleteById(id);
    expect(deleted).toBe(true);
    expect(repo.findAll().length).toBe(0);
  });

  test('FeatureFlagRepository seeds and toggles flags', () => {
    const repo = new FeatureFlagRepository(db);
    const map = repo.findAllAsMap();
    expect(map.blacklist).toBe(true);

    const ok = repo.setEnabled('blacklist', false);
    expect(ok).toBe(true);
    const map2 = repo.findAllAsMap();
    expect(map2.blacklist).toBe(false);
  });

  test('FloodRateRepository seeds, updates, and logs', () => {
    const repo = new FloodRateRepository(db);
    const rates = repo.findAll();
    expect(rates.length).toBeGreaterThanOrEqual(3);

    const r = repo.findByType('udp_flood');
    expect(r).toBeDefined();

    const updated = repo.update('udp_flood', 1, 2);
    expect(updated).toBe(true);

    const logId = repo.addLog('udp_flood', '1.2.3.4', 'soft_limit_hit');
    expect(typeof logId).toBe('number');

    const logs = repo.getLogs(10);
    expect(logs.length).toBeGreaterThanOrEqual(1);
  });
});
