const FloodService = require("../services/FloodService");

describe("FloodService (unit)", () => {
  let featureRepo, floodRepo, ipc, svc;

  beforeEach(() => {
    featureRepo = {
      findAllAsMap: jest.fn().mockReturnValue({ udp_flood: true, icmp_flood: false }),
      setEnabled: jest.fn().mockReturnValue(true),
    };

    floodRepo = {
      findAll: jest.fn().mockReturnValue([
        { flood_type: "udp_flood", soft_limit: 10, hard_limit: 100 },
      ]),
      findByType: jest.fn().mockImplementation((t) => (t === "udp_flood" ? { flood_type: "udp_flood", soft_limit: 10, hard_limit: 100 } : null)),
      update: jest.fn().mockReturnValue(true),
      getLogs: jest.fn().mockReturnValue([]),
      getLogsByIp: jest.fn().mockReturnValue([]),
      addLog: jest.fn().mockReturnValue(7),
    };

    ipc = { send: jest.fn() };

    svc = new FloodService(featureRepo, floodRepo, ipc);
  });

  test("getAllFloodConfigs combines rates and flags", () => {
    const configs = svc.getAllFloodConfigs();
    expect(configs).toHaveLength(1);
    expect(configs[0]).toMatchObject({ flood_type: "udp_flood", enabled: true });
  });

  test("getFloodConfig invalid type throws", () => {
    expect(() => svc.getFloodConfig("bad_type")).toThrow(/Invalid flood type/);
  });

  test("setFloodEnabled calls repo and ipc", () => {
    const res = svc.setFloodEnabled("udp_flood", false);
    expect(featureRepo.setEnabled).toHaveBeenCalledWith("udp_flood", false);
    expect(ipc.send).toHaveBeenCalledWith({ action: "toggle_feature", feature: "udp_flood", enabled: 0 });
    expect(res).toBe(true);
  });

  test("updateFloodRates validates limits", () => {
    expect(() => svc.updateFloodRates("udp_flood", 10, 5)).toThrow(/Soft limit must be less than hard limit/);
    const ok = svc.updateFloodRates("udp_flood", 5, 10);
    expect(floodRepo.update).toHaveBeenCalledWith("udp_flood", 5, 10);
    expect(ipc.send).toHaveBeenCalledWith({ action: "update_flood_rates", flood_type: "udp_flood", soft_limit: 5, hard_limit: 10 });
    expect(ok).toBe(true);
  });

  test("addFloodLog validates event and type", () => {
    expect(() => svc.addFloodLog("bad", "1.2.3.4", "soft_limit_hit")).toThrow(/Invalid flood type/);
    expect(() => svc.addFloodLog("udp_flood", "1.2.3.4", "unknown_event")).toThrow(/Invalid event/);
    const id = svc.addFloodLog("udp_flood", "1.2.3.4", "soft_limit_hit");
    expect(id).toBe(7);
  });
});
