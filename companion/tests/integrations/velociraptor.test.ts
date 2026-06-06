import { describe, it, expect } from "vitest";
import {
  parseVqlOutput,
  VelociraptorClient,
  loadVelociraptorConfig,
  buildVelociraptorClient,
  type VelociraptorApiConfig,
  type VqlRunner,
} from "../../src/integrations/velociraptor/velociraptorApi.js";

const cfg: VelociraptorApiConfig = {
  apiConfigPath: "/tmp/api.config.yaml",
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 3,
  maxOutputBytes: 1024,
};

describe("parseVqlOutput", () => {
  it("parses a JSON array of rows", () => {
    expect(parseVqlOutput('[{"a":1},{"a":2}]')).toEqual([{ a: 1 }, { a: 2 }]);
  });
  it("parses JSONL output", () => {
    expect(parseVqlOutput('{"a":1}\n{"a":2}\n')).toEqual([{ a: 1 }, { a: 2 }]);
  });
  it("wraps a single object in an array", () => {
    expect(parseVqlOutput('{"a":1}')).toEqual([{ a: 1 }]);
  });
  it("skips non-JSON noise lines in JSONL mode", () => {
    expect(parseVqlOutput('log line\n{"a":1}')).toEqual([{ a: 1 }]);
  });
  it("returns [] for empty or non-JSON output", () => {
    expect(parseVqlOutput("")).toEqual([]);
    expect(parseVqlOutput("not json")).toEqual([]);
  });
});

describe("VelociraptorClient", () => {
  it("runs VQL via the injected runner and returns rows", async () => {
    let seen = "";
    const runner: VqlRunner = async (vql) => { seen = vql; return { rows: [{ Pid: 1 }, { Pid: 2 }], raw: "" }; };
    const client = new VelociraptorClient(cfg, runner);
    const res = await client.run("SELECT * FROM pslist()");
    expect(seen).toBe("SELECT * FROM pslist()");
    expect(res.rows).toHaveLength(2);
    expect(res.total).toBe(2);
    expect(res.truncated).toBe(false);
  });

  it("caps rows at maxRows and flags truncation", async () => {
    const runner: VqlRunner = async () => ({ rows: [1, 2, 3, 4, 5].map((n) => ({ n })), raw: "" });
    const res = await new VelociraptorClient(cfg, runner).run("SELECT 1");
    expect(res.rows).toHaveLength(3);     // maxRows
    expect(res.total).toBe(5);
    expect(res.truncated).toBe(true);
  });

  it("trims VQL and rejects an empty query", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    await expect(new VelociraptorClient(cfg, runner).run("   ")).rejects.toThrow(/VQL is required/);
  });

  it("propagates runner errors", async () => {
    const runner: VqlRunner = async () => { throw new Error("boom"); };
    await expect(new VelociraptorClient(cfg, runner).run("SELECT 1")).rejects.toThrow(/boom/);
  });
});

describe("loadVelociraptorConfig / buildVelociraptorClient", () => {
  it("returns null/undefined when DFIR_VELOCIRAPTOR_API_CONFIG is unset", () => {
    expect(loadVelociraptorConfig({})).toBeNull();
    expect(buildVelociraptorClient({})).toBeUndefined();
  });
  it("loads config with defaults when the api config path is set", () => {
    const c = loadVelociraptorConfig({ DFIR_VELOCIRAPTOR_API_CONFIG: "/x/api.yaml" });
    expect(c).toMatchObject({ apiConfigPath: "/x/api.yaml", binary: "velociraptor" });
    expect(c!.timeoutMs).toBeGreaterThan(0);
    expect(c!.maxRows).toBeGreaterThan(0);
  });
  it("honors binary/timeout/row overrides", () => {
    const c = loadVelociraptorConfig({
      DFIR_VELOCIRAPTOR_API_CONFIG: "/x/api.yaml",
      DFIR_VELOCIRAPTOR_BINARY: "/opt/velociraptor.exe",
      DFIR_VELOCIRAPTOR_TIMEOUT_MS: "12000",
      DFIR_VELOCIRAPTOR_MAX_ROWS: "50",
    });
    expect(c).toMatchObject({ binary: "/opt/velociraptor.exe", timeoutMs: 12000, maxRows: 50 });
    expect(buildVelociraptorClient({ DFIR_VELOCIRAPTOR_API_CONFIG: "/x/api.yaml" })).toBeInstanceOf(VelociraptorClient);
  });
});
