import { describe, it, expect } from "vitest";
import {
  VelociraptorClient,
  type VelociraptorApiConfig,
  type VqlRunner,
} from "../../src/integrations/velociraptor/velociraptorApi.js";
import {
  parseReachedClients,
  readHuntCoverage,
} from "../../src/integrations/velociraptor/huntReachedClients.js";

// #1625 — Velociraptor schedules a hunt on a client only when it checks in, so an empty result speaks
// only for the clients whose flow finished without error. The collect records them per client.

const cfg: VelociraptorApiConfig = {
  apiConfigPath: "/tmp/api.config.yaml",
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 3,
  maxOutputBytes: 1024,
};

const row = (over: Record<string, unknown> = {}) => ({
  ClientId: "C.1",
  State: "FINISHED",
  Status: "",
  Hostname: "WS01",
  Fqdn: "ws01.example.com",
  OS: "windows",
  ...over,
});

describe("parseReachedClients (#1625)", () => {
  it("keeps only flows that finished without an error status", () => {
    const rows = [
      row(),
      row({ ClientId: "C.2", State: "ERROR", Status: "query failed", Hostname: "WS02" }),
      row({ ClientId: "C.3", State: "RUNNING", Hostname: "WS03" }),
      row({ ClientId: "C.4", State: "WAITING", Hostname: "WS04" }),
      row({ ClientId: "C.5", State: "IN_PROGRESS", Hostname: "WS05" }),
      row({ ClientId: "C.6", State: "UNRESPONSIVE", Hostname: "WS06" }),
      row({ ClientId: "C.7", State: "FINISHED", Status: "artifact failed", Hostname: "WS07" }),
      row({ ClientId: "C.8", State: "finished", Status: undefined, Hostname: "web08", OS: "Linux" }),
    ];
    expect(parseReachedClients(rows)).toEqual([
      { clientId: "C.1", hostname: "WS01", fqdn: "ws01.example.com", os: "windows" },
      { clientId: "C.8", hostname: "web08", fqdn: "ws01.example.com", os: "linux" },
    ]);
  });

  it("zero rows is an authoritative empty list", () => {
    expect(parseReachedClients([])).toEqual([]);
  });

  it("skips a finished flow whose client has no name left (deleted client)", () => {
    expect(parseReachedClients([row({ Hostname: "", Fqdn: undefined })])).toEqual([]);
  });

  it("any row of an unexpected shape makes the whole list unknown", () => {
    for (const bad of [
      "junk",
      [null],
      [[1]],
      [row({ ClientId: "not-a-client" })],
      [row({ State: 2 })],
      [row({ Status: { code: 1 } })],
      [row(), row({ ClientId: undefined })],
    ])
      expect(parseReachedClients(bad)).toBeUndefined();
  });
});

describe("VelociraptorClient.huntReachedClients (#1625)", () => {
  it("reads hunt_flows for the hunt, with each client's names and OS", async () => {
    let program = "";
    const runner: VqlRunner = async (s) => {
      program = s[0];
      return { rows: [row()], raw: "" };
    };
    const got = await new VelociraptorClient(cfg, runner).huntReachedClients("H.ABC123");
    expect(got).toEqual([{ clientId: "C.1", hostname: "WS01", fqdn: "ws01.example.com", os: "windows" }]);
    expect(program).toContain("FROM hunt_flows(hunt_id='H.ABC123')");
    expect(program).toContain("Flow.state AS State");
    expect(program).toContain("os_info.system AS OS");
  });

  it("rejects an invalid hunt id before any VQL runs", async () => {
    const runner: VqlRunner = async () => {
      throw new Error("must not run");
    };
    await expect(new VelociraptorClient(cfg, runner).huntReachedClients("x' OR 1")).rejects.toThrow(
      /invalid hunt id/,
    );
  });
});

describe("readHuntCoverage (#1625)", () => {
  it("a failed read of either part leaves that part unknown and never throws", async () => {
    const got = await readHuntCoverage(
      {
        huntStatus: async () => {
          throw new Error("down");
        },
        huntReachedClients: async () => {
          throw new Error("down");
        },
      },
      "H.1",
    );
    expect(got).toEqual({ live: null });
  });

  it("a client without the per-host read leaves the list unknown", async () => {
    const got = await readHuntCoverage({ huntStatus: async () => ({ state: "STOPPED" }) }, "H.1");
    expect(got).toEqual({ live: { state: "STOPPED" } });
  });
});
