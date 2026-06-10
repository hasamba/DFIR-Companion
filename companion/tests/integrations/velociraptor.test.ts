import { describe, it, expect } from "vitest";
import {
  parseVqlOutput,
  splitVqlStatements,
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

describe("splitVqlStatements", () => {
  it("strips the leading comment so the query does not start with '--' (the CLI flag-parse bug)", () => {
    const vql = "-- file presence (exact path) + its hashes\nSELECT FullPath FROM glob(globs=\"C:/x\")";
    const out = splitVqlStatements(vql);
    expect(out).toHaveLength(1);
    expect(out[0].startsWith("--")).toBe(false);
    expect(out[0]).toBe('SELECT FullPath FROM glob(globs="C:/x")');
  });
  it("splits multiple blank-line-separated pivots into separate statements", () => {
    const vql = "-- a\nSELECT 1\n\n-- b\nSELECT 2";
    expect(splitVqlStatements(vql)).toEqual(["SELECT 1", "SELECT 2"]);
  });
  it("drops comment-only chunks and keeps inline comments on VQL lines", () => {
    const vql = "-- header only\n\nSELECT 1 -- inline keeps";
    expect(splitVqlStatements(vql)).toEqual(["SELECT 1 -- inline keeps"]);
  });
  it("returns [] when there is no real VQL", () => {
    expect(splitVqlStatements("-- just a comment\n-- another")).toEqual([]);
    expect(splitVqlStatements("   ")).toEqual([]);
  });
});

describe("VelociraptorClient.run (server-side)", () => {
  it("splits VQL into statements (comments stripped) and returns rows", async () => {
    let seen: string[] = [];
    const runner: VqlRunner = async (statements) => { seen = statements; return { rows: [{ Pid: 1 }, { Pid: 2 }], raw: "" }; };
    const res = await new VelociraptorClient(cfg, runner).run("-- c\nSELECT * FROM pslist()");
    expect(seen).toEqual(["SELECT * FROM pslist()"]);
    expect(res.rows).toHaveLength(2);
    expect(res.total).toBe(2);
  });

  it("caps rows at maxRows and flags truncation", async () => {
    const runner: VqlRunner = async () => ({ rows: [1, 2, 3, 4, 5].map((n) => ({ n })), raw: "" });
    const res = await new VelociraptorClient(cfg, runner).run("SELECT 1");
    expect(res.rows).toHaveLength(3);     // maxRows
    expect(res.total).toBe(5);
    expect(res.truncated).toBe(true);
  });

  it("rejects a query that has no runnable VQL", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    await expect(new VelociraptorClient(cfg, runner).run("-- only a comment")).rejects.toThrow(/No runnable VQL/);
  });

  it("propagates runner errors", async () => {
    const runner: VqlRunner = async () => { throw new Error("boom"); };
    await expect(new VelociraptorClient(cfg, runner).run("SELECT 1")).rejects.toThrow(/boom/);
  });
});

describe("VelociraptorClient.launchHunt", () => {
  it("packages the pivots as a CLIENT artifact and launches a hunt across all clients", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => {
      program = statements[0];   // launchHunt runs one orchestration program
      return { rows: [{ Hunt: { HuntId: "H.ABC123", state: "RUNNING" } }], raw: "" };
    };
    const res = await new VelociraptorClient({ ...cfg, guiUrl: "https://velo.example/" }, runner)
      .launchHunt("-- file presence\nSELECT FullPath FROM glob(globs=\"C:/**/x.exe\")", "find x.exe");
    expect(res.huntId).toBe("H.ABC123");
    expect(res.artifact).toBe("Custom.Hunt.Companion.find_x_exe");
    expect(res.sources).toEqual(["Pivot0"]);
    expect(res.state).toBe("RUNNING");
    expect(res.guiUrl).toBe("https://velo.example/app/index.html?org_id=root#/hunts/H.ABC123");
    // The orchestration program defines a CLIENT artifact and launches a hunt on it.
    expect(program).toContain("artifact_set(");
    expect(program).toContain("type: CLIENT");
    expect(program).toContain("hunt(");
    expect(program).toContain("Custom.Hunt.Companion.find_x_exe");
    expect(program).not.toContain("-- file presence");   // comments stripped from the artifact source
  });

  it("makes one artifact source per pivot statement", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ Hunt: { HuntId: "H.X1", state: "RUNNING" } }], raw: "" }; };
    const res = await new VelociraptorClient(cfg, runner).launchHunt("SELECT 1\n\nSELECT 2", "multi");
    expect(res.sources).toEqual(["Pivot0", "Pivot1"]);
    expect(program).toContain("name: Pivot0");
    expect(program).toContain("name: Pivot1");
  });

  it("strips backslashes/quotes from an event-label description (YAML/VQL safety)", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ Hunt: { HuntId: "H.X2", state: "RUNNING" } }], raw: "" }; };
    await new VelociraptorClient(cfg, runner).launchHunt(
      "SELECT FullPath FROM glob(globs=\"C:/x\")",
      'Velociraptor detection: Mimikatz Tools - \\\\.\\C:\\Tools\\mimidrv.sys',
    );
    expect(program).not.toContain("\\");   // no backslashes survive into the embedded YAML/VQL
    expect(program).toContain('description: "Velociraptor detection: Mimikatz Tools - .C:Toolsmimidrv.sys"');
  });

  it("throws when no hunt id comes back", async () => {
    const runner: VqlRunner = async () => ({ rows: [{ Hunt: {} }], raw: "" });
    await expect(new VelociraptorClient(cfg, runner).launchHunt("SELECT 1", "x")).rejects.toThrow(/hunt id/);
  });
});

describe("VelociraptorClient.huntResults", () => {
  it("reads a single-source hunt's results via artifact/source notation", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ Name: "evil.exe", ClientId: "C.1" }], raw: "" }; };
    const res = await new VelociraptorClient(cfg, runner).huntResults("H.ABC123", "Custom.Hunt.Companion.x", ["Pivot0"]);
    expect(program).toBe("SELECT * FROM hunt_results(hunt_id='H.ABC123', artifact='Custom.Hunt.Companion.x/Pivot0') LIMIT 4");
    expect(res.rows).toHaveLength(1);
  });

  it("injects an analyst WHERE filter BEFORE the LIMIT (so it drops noise at the source)", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [], raw: "" }; };
    await new VelociraptorClient(cfg, runner).huntResults("H.ABC123", "DetectRaptor.X", [], "NOT OSPath =~ 'pagefile'");
    expect(program).toBe("SELECT * FROM hunt_results(hunt_id='H.ABC123', artifact='DetectRaptor.X') WHERE (NOT OSPath =~ 'pagefile') LIMIT 4");
  });

  it("chains hunt_results across multiple sources (artifact/source refs)", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [], raw: "" }; };
    await new VelociraptorClient(cfg, runner).huntResults("H.ABC123", "Custom.Hunt.Companion.x", ["Pivot0", "Pivot1"]);
    expect(program).toContain("chain(");
    expect(program).toContain("artifact='Custom.Hunt.Companion.x/Pivot0'");
    expect(program).toContain("artifact='Custom.Hunt.Companion.x/Pivot1'");
  });

  it("rejects malformed ids (no VQL-string injection)", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    const c = new VelociraptorClient(cfg, runner);
    await expect(c.huntResults("H.x' OR 1=1--", "Custom.x", [])).rejects.toThrow(/invalid hunt id/);
    await expect(c.huntResults("H.ABC", "bad name", [])).rejects.toThrow(/invalid artifact/);
  });
});

describe("VelociraptorClient.listClientArtifacts", () => {
  it("queries client artifact_definitions and returns name+description without the row cap", async () => {
    let program = "";
    const rows = Array.from({ length: 10 }, (_, i) => ({ name: `Windows.Test.A${i}`, description: `d${i}`, type: "CLIENT" }));
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows, raw: "" }; };
    const out = await new VelociraptorClient(cfg, runner).listClientArtifacts();   // cfg.maxRows = 3
    expect(program).toContain("artifact_definitions()");
    expect(program.toLowerCase()).toContain("client");
    expect(out).toHaveLength(10);   // metadata, NOT capped at maxRows
    expect(out[0]).toEqual({ name: "Windows.Test.A0", description: "d0" });
  });
});

describe("VelociraptorClient.launchArtifactHunt", () => {
  it("launches a hunt over the chosen artifacts and returns the hunt id + gui link", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ Hunt: { HuntId: "H.B1", state: "RUNNING" } }], raw: "" }; };
    const res = await new VelociraptorClient({ ...cfg, guiUrl: "https://velo.example/" }, runner)
      .launchArtifactHunt(["Windows.System.Pslist", "Windows.Network.Netstat"], "Fast Triage");
    expect(res.huntId).toBe("H.B1");
    expect(res.artifacts).toEqual(["Windows.System.Pslist", "Windows.Network.Netstat"]);
    expect(res.guiUrl).toBe("https://velo.example/app/index.html?org_id=root#/hunts/H.B1");
    expect(program).toContain("hunt(");
    expect(program).toContain("artifacts=['Windows.System.Pslist', 'Windows.Network.Netstat']");
  });

  it("adds include/exclude label + OS clauses and sanitizes label values", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ Hunt: { HuntId: "H.B2", state: "RUNNING" } }], raw: "" }; };
    await new VelociraptorClient(cfg, runner).launchArtifactHunt(["Windows.System.Pslist"], "x", {
      includeLabels: ["workstations"], excludeLabels: ["servers", "bad'; DROP"], os: "windows",
    });
    expect(program).toContain("include_labels=['workstations']");
    expect(program).toContain("exclude_labels=['servers', 'bad DROP']");   // quote + semicolon stripped
    expect(program).toContain("os='windows'");
  });

  it("ignores an unknown os and omits empty label clauses", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ Hunt: { HuntId: "H.B4", state: "RUNNING" } }], raw: "" }; };
    await new VelociraptorClient(cfg, runner).launchArtifactHunt(["Windows.System.Pslist"], "x", { os: "solaris" as never });
    expect(program).not.toContain("os=");
    expect(program).not.toContain("include_labels=");
    expect(program).not.toContain("exclude_labels=");
  });

  it("puts ?org_id before the # fragment and honors a custom org", async () => {
    const runner: VqlRunner = async () => ({ rows: [{ Hunt: { HuntId: "H.ORG1", state: "RUNNING" } }], raw: "" });
    const res = await new VelociraptorClient({ ...cfg, guiUrl: "https://velo:5888", guiOrg: "OACME" }, runner)
      .launchArtifactHunt(["Windows.System.Pslist"], "x");
    expect(res.guiUrl).toBe("https://velo:5888/app/index.html?org_id=OACME#/hunts/H.ORG1");
  });

  it("adds a collection timeout clause when timeoutSeconds is set, omits it otherwise", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ Hunt: { HuntId: "H.B5", state: "RUNNING" } }], raw: "" }; };
    const c = new VelociraptorClient(cfg, runner);
    await c.launchArtifactHunt(["Windows.System.Pslist"], "x", {}, { timeoutSeconds: 3600 });
    expect(program).toContain("timeout=3600");
    await c.launchArtifactHunt(["Windows.System.Pslist"], "x", {}, { timeoutSeconds: 0 });
    expect(program).not.toContain("timeout=");
  });

  it("passes per-artifact parameters as a hunt spec (only for artifacts in the hunt)", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ Hunt: { HuntId: "H.SP1", state: "RUNNING" } }], raw: "" }; };
    await new VelociraptorClient(cfg, runner).launchArtifactHunt(
      ["Windows.Hayabusa.Rules", "Windows.System.Pslist"], "x", {},
      { params: { "Windows.Hayabusa.Rules": { RuleLevel: "Critical, High, and Medium" }, "Not.In.Hunt": { X: "y" } } },
    );
    expect(program).toContain("spec=dict(`Windows.Hayabusa.Rules`=dict(RuleLevel='Critical, High, and Medium'))");
    expect(program).not.toContain("Not.In.Hunt");   // params for an artifact not in the hunt are dropped
  });

  it("omits the spec clause when there are no params", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ Hunt: { HuntId: "H.SP2", state: "RUNNING" } }], raw: "" }; };
    await new VelociraptorClient(cfg, runner).launchArtifactHunt(["Windows.System.Pslist"], "x");
    expect(program).not.toContain("spec=");
  });

  it("rejects an injection-y artifact name and an empty list", async () => {
    const runner: VqlRunner = async () => ({ rows: [{ Hunt: { HuntId: "H.B3" } }], raw: "" });
    const c = new VelociraptorClient(cfg, runner);
    await expect(c.launchArtifactHunt(["Windows.System.Pslist", "bad name'"], "x")).rejects.toThrow(/invalid artifact/);
    await expect(c.launchArtifactHunt([], "x")).rejects.toThrow(/no artifacts/);
  });

  it("throws when no hunt id comes back", async () => {
    const runner: VqlRunner = async () => ({ rows: [{ Hunt: {} }], raw: "" });
    await expect(new VelociraptorClient(cfg, runner).launchArtifactHunt(["Windows.System.Pslist"], "x")).rejects.toThrow(/hunt id/);
  });
});

describe("VelociraptorClient.huntResultsByArtifact", () => {
  it("builds an artifact-map keyed by artifact, dropping artifacts with no rows yet", async () => {
    const runner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("Pslist")) return { rows: [{ Name: "evil.exe" }], raw: "" };
      return { rows: [], raw: "" };   // Netstat returns nothing yet
    };
    const { results, skipped } = await new VelociraptorClient(cfg, runner).huntResultsByArtifact("H.ABC123", ["Windows.System.Pslist", "Windows.Network.Netstat"]);
    expect(Object.keys(results)).toEqual(["Windows.System.Pslist"]);
    expect(results["Windows.System.Pslist"]).toHaveLength(1);
    expect(skipped).toEqual([]);
  });

  it("is resilient: an artifact whose fetch fails (oversized) is skipped, the rest still import", async () => {
    const runner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("Hayabusa")) throw new Error("output exceeded 52428800 bytes");
      return { rows: [{ Name: "ok" }], raw: "" };
    };
    const { results, skipped } = await new VelociraptorClient(cfg, runner).huntResultsByArtifact("H.ABC123", ["Windows.Hayabusa.Rules", "Windows.System.Pslist"]);
    expect(skipped).toEqual(["Windows.Hayabusa.Rules"]);
    expect(Object.keys(results)).toEqual(["Windows.System.Pslist"]);
  });

  it("applies the per-artifact WHERE filter from the filters map", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ a: 1 }], raw: "" }; };
    await new VelociraptorClient(cfg, runner).huntResultsByArtifact("H.OK1", ["DetectRaptor.X"], { "DetectRaptor.X": "NOT OSPath =~ 'pagefile'" });
    expect(program).toContain("WHERE (NOT OSPath =~ 'pagefile')");
  });

  it("rejects a malformed hunt id and skips invalid artifact names", async () => {
    const runner: VqlRunner = async () => ({ rows: [{ a: 1 }], raw: "" });
    const c = new VelociraptorClient(cfg, runner);
    await expect(c.huntResultsByArtifact("bad id", ["Windows.System.Pslist"])).rejects.toThrow(/invalid hunt id/);
    const { results } = await c.huntResultsByArtifact("H.OK1", ["bad name", "Windows.System.Pslist"]);
    expect(Object.keys(results)).toEqual(["Windows.System.Pslist"]);
  });
});

describe("VelociraptorClient.huntUploads", () => {
  it("reads .json upload content, drops empties, and substitutes the hunt id into the VQL", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => {
      program = statements[0];
      return { rows: [
        { ClientId: "C.1", Path: "C:/t/report.json", Name: "report.json", Content: '{"a":1}' },
        { ClientId: "C.2", Path: "C:/t/empty.json", Name: "empty.json", Content: "" },
      ], raw: "" };
    };
    const ups = await new VelociraptorClient(cfg, runner).huntUploads("H.UP1");
    expect(program).toContain("hunt_flows(hunt_id='H.UP1')");
    expect(program).not.toContain("__HUNT_ID__");
    expect(ups).toHaveLength(1);   // the empty-content row is dropped
    expect(ups[0]).toEqual({ name: "report.json", clientId: "C.1", content: '{"a":1}' });
  });

  it("uses the configured override VQL (DFIR_VELOCIRAPTOR_UPLOAD_VQL) when set", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [], raw: "" }; };
    await new VelociraptorClient({ ...cfg, uploadVql: "SELECT * FROM custom(hunt='__HUNT_ID__')" }, runner).huntUploads("H.UP2");
    expect(program).toBe("SELECT * FROM custom(hunt='H.UP2')");
  });

  it("rejects a malformed hunt id (no VQL-string injection)", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    await expect(new VelociraptorClient(cfg, runner).huntUploads("bad id")).rejects.toThrow(/invalid hunt id/);
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
