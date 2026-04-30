const FirewallService = require("../services/FirewallService");

describe("FirewallService (unit)", () => {
  let featureRepo, blacklistRepo, portRepo, ipc, svc;

  beforeEach(() => {
    featureRepo = {
      findAllAsMap: jest.fn().mockReturnValue({ blacklist: true, ping: false, port: true }),
      setEnabled: jest.fn(),
    };

    blacklistRepo = {
      findAll: jest.fn().mockReturnValue([]),
      create: jest.fn().mockReturnValue(1),
      findById: jest.fn(),
      deleteById: jest.fn(),
    };

    portRepo = {
      findAll: jest.fn().mockReturnValue([]),
      create: jest.fn().mockReturnValue(2),
      findById: jest.fn(),
      deleteById: jest.fn(),
    };

    ipc = { send: jest.fn() };

    svc = new FirewallService(featureRepo, blacklistRepo, portRepo, ipc);
  });

  test("getFeatures returns repository map", () => {
    expect(svc.getFeatures()).toEqual({ blacklist: true, ping: false, port: true });
    expect(featureRepo.findAllAsMap).toHaveBeenCalled();
  });

  test("toggleFeature valid calls repo and ipc", () => {
    const res = svc.toggleFeature("blacklist", false);
    expect(featureRepo.setEnabled).toHaveBeenCalledWith("blacklist", false);
    expect(ipc.send).toHaveBeenCalledWith({ action: "toggle_feature", feature: "blacklist", enabled: 0 });
    expect(res).toEqual({ feature: "blacklist", enabled: false });
  });

  test("toggleFeature invalid feature throws", () => {
    expect(() => svc.toggleFeature("nosuch", true)).toThrow(/Unknown feature/);
  });

  test("addToBlacklist rejects invalid IP", () => {
    expect(() => svc.addToBlacklist("not.an.ip")).toThrow(/Invalid IPv4 address/);
  });

  test("addToBlacklist duplicate error converted", () => {
    blacklistRepo.create.mockImplementation(() => { throw new Error("UNIQUE constraint failed"); });
    expect(() => svc.addToBlacklist("1.2.3.4")).toThrow(/already exists in blacklist/);
  });

  test("removeFromBlacklist not found throws", () => {
    blacklistRepo.findById.mockReturnValue(null);
    expect(() => svc.removeFromBlacklist(9)).toThrow(/not found/);
  });

  test("addPort validates port range and calls ipc", () => {
    expect(() => svc.addPort(70000)).toThrow(/Invalid port/);
    const out = svc.addPort(8080, "note");
    expect(portRepo.create).toHaveBeenCalledWith(8080, "note");
    expect(ipc.send).toHaveBeenCalledWith({ action: "add_port", port: 8080 });
    expect(out.port).toBe(8080);
  });

  test("removePort not found throws", () => {
    portRepo.findById.mockReturnValue(null);
    expect(() => svc.removePort(5)).toThrow(/not found/);
  });
});
