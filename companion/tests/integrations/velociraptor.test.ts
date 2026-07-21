import { describe, it, expect } from "vitest";
import {
  parseVqlOutput,
  sanitizeVqlDurations,
  splitVqlStatements,
  VelociraptorClient,
  extractMonitoredArtifacts,
  loadVelociraptorConfig,
  buildVelociraptorClient,
  retryTransientSpawn,
  spawnErrorMessage,
  translateVelociraptorError,
  matchClient,
  normalizeClientRow,
  normalizeHuntExpirySeconds,
  DEFAULT_HUNT_EXPIRY_SECONDS,
  parseArtifactParams,
  type VeloClientRecord,
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

describe("sanitizeVqlDurations", () => {
  it("rewrites day suffix to seconds arithmetic", () => {
    expect(sanitizeVqlDurations("WHERE TimeCreated > now() - 30d")).toBe("WHERE TimeCreated > now() - 30 * 86400");
  });
  it("rewrites hour suffix", () => {
    expect(sanitizeVqlDurations("now() - 24h")).toBe("now() - 24 * 3600");
  });
  it("rewrites week suffix", () => {
    expect(sanitizeVqlDurations("now() - 2w")).toBe("now() - 2 * 604800");
  });
  it("rewrites minute suffix", () => {
    expect(sanitizeVqlDurations("now() - 15m")).toBe("now() - 15 * 60");
  });
  it("handles whitespace between operator and number", () => {
    expect(sanitizeVqlDurations("now() -  7d")).toBe("now() - 7 * 86400");
  });
  it("rewrites addition context too", () => {
    expect(sanitizeVqlDurations("now() + 1d")).toBe("now() + 1 * 86400");
  });
  it("does not touch standalone 'd' not preceded by operator+number", () => {
    expect(sanitizeVqlDurations("SELECT d FROM foo()")).toBe("SELECT d FROM foo()");
  });
  it("does not mangle file paths like %4Operational or 30day_archive", () => {
    const q = 'parse_evtx(files="C:/Logs/Windows Defender%4Operational.evtx")';
    expect(sanitizeVqlDurations(q)).toBe(q);
    const q2 = 'glob(globs="C:/data/30day_archive/**")';
    expect(sanitizeVqlDurations(q2)).toBe(q2);
  });
  it("rewrites the exact failing query from issue", () => {
    const input = 'SELECT * FROM parse_evtx(files="C:/Windows/System32/Winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx") WHERE System.EventID.Value = 5001 AND TimeCreated > now() - 30d';
    const out = sanitizeVqlDurations(input);
    expect(out).toContain("30 * 86400");
    expect(out).not.toContain("30d");
    expect(out).toContain("%4Operational");
  });
});

describe("splitVqlStatements", () => {
  it("strips the leading comment so the query does not start with '--' (the CLI flag-parse bug)", () => {
    const vql = "-- file presence (exact path) + its hashes\nSELECT OSPath FROM glob(globs=\"C:/x\")";
    const out = splitVqlStatements(vql);
    expect(out).toHaveLength(1);
    expect(out[0].startsWith("--")).toBe(false);
    expect(out[0]).toBe('SELECT OSPath FROM glob(globs="C:/x")');
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

describe("normalizeHuntExpirySeconds", () => {
  it("defaults to one hour on missing / non-positive / non-numeric input", () => {
    expect(DEFAULT_HUNT_EXPIRY_SECONDS).toBe(3600);
    expect(normalizeHuntExpirySeconds(undefined)).toBe(3600);
    expect(normalizeHuntExpirySeconds(null)).toBe(3600);
    expect(normalizeHuntExpirySeconds(0)).toBe(3600);
    expect(normalizeHuntExpirySeconds(-5)).toBe(3600);
    expect(normalizeHuntExpirySeconds("nope")).toBe(3600);
    expect(normalizeHuntExpirySeconds(NaN)).toBe(3600);
  });
  it("passes through the relative presets", () => {
    expect(normalizeHuntExpirySeconds(3600)).toBe(3600);      // 1 hour
    expect(normalizeHuntExpirySeconds(86_400)).toBe(86_400);   // 1 day
    expect(normalizeHuntExpirySeconds(604_800)).toBe(604_800); // 1 week
    expect(normalizeHuntExpirySeconds("86400")).toBe(86_400);  // numeric string
  });
  it("clamps to [60s, 30d] and floors fractional seconds", () => {
    expect(normalizeHuntExpirySeconds(10)).toBe(60);            // below the floor
    expect(normalizeHuntExpirySeconds(99_999_999)).toBe(2_592_000);   // above the 30-day ceiling
    expect(normalizeHuntExpirySeconds(3600.9)).toBe(3600);
  });
  it("honors a custom fallback", () => {
    expect(normalizeHuntExpirySeconds(undefined, 86_400)).toBe(86_400);
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
      .launchHunt("-- file presence\nSELECT OSPath FROM glob(globs=\"C:/**/x.exe\")", "find x.exe");
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
    expect(program).toContain("expires=now() + 3600");   // default one-hour expiry
    expect(program).not.toContain("-- file presence");   // comments stripped from the artifact source
  });

  it("uses a supplied relative expiry (seconds)", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ Hunt: { HuntId: "H.EXP", state: "RUNNING" } }], raw: "" }; };
    await new VelociraptorClient(cfg, runner).launchHunt("SELECT 1", "x", { expirySeconds: 604_800 });
    expect(program).toContain("expires=now() + 604800");   // one week
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
      "SELECT OSPath FROM glob(globs=\"C:/x\")",
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

// A runner for the collect flow: branches on the inventory query (FROM clients) vs the collect program
// (collect_client). `clientRows` are returned for listClients(); the collect program returns a flow.
function collectRunner(clientRows: unknown[], flow: Record<string, unknown> = { flow_id: "F.flow1" }) {
  const programs: string[] = [];
  const runner: VqlRunner = async (statements) => {
    const p = statements[0];
    programs.push(p);
    if (p.includes("collect_client(")) return { rows: [{ Flow: flow }], raw: "" };
    if (p.includes("FROM clients(")) return { rows: clientRows, raw: "" };
    return { rows: [], raw: "" };
  };
  return { runner, programs };
}

describe("VelociraptorClient.listClients", () => {
  it("normalizes clients() rows into inventory records", async () => {
    const runner: VqlRunner = async () => ({ rows: [
      { client_id: "C.win11", os_info: { hostname: "WIN11", fqdn: "WIN11.windomain.local" }, last_seen_at: "2026-06-01" },
      { client_id: "C.kali", os_info: { hostname: "kaliPurple", fqdn: "kaliPurple.windomain.local" } },
      { client_id: "bogus", os_info: { hostname: "x" } },   // invalid id → dropped
    ], raw: "" });
    const out = await new VelociraptorClient(cfg, runner).listClients();
    expect(out).toEqual([
      { clientId: "C.win11", hostname: "WIN11", fqdn: "WIN11.windomain.local", lastSeen: "2026-06-01" },
      { clientId: "C.kali", hostname: "kaliPurple", fqdn: "kaliPurple.windomain.local" },
    ]);
  });
});

describe("VelociraptorClient.collectOnClient", () => {
  it("packages the VQL as a CLIENT artifact and collect_clients the given client id", async () => {
    const { runner, programs } = collectRunner([]);
    const res = await new VelociraptorClient({ ...cfg, guiUrl: "https://velo.example/" }, runner)
      .collectOnClient("C.abc", "-- persistence\nSELECT Name FROM Artifact.Windows.System.Services()", "services on WIN11", "WIN11.windomain.local");
    expect(res.clientId).toBe("C.abc");
    expect(res.flowId).toBe("F.flow1");
    expect(res.hostname).toBe("WIN11.windomain.local");
    expect(res.artifact).toBe("Custom.Collect.Companion.services_on_WIN11");
    expect(res.guiUrl).toBe("https://velo.example/app/index.html?org_id=root#/collected/C.abc/F.flow1");
    expect(res.sources).toEqual(["Pivot0"]);   // for reading results back via collectionResults
    const prog = programs.find((p) => p.includes("collect_client(")) || "";
    expect(prog).toContain("type: CLIENT");
    expect(prog).toContain("collect_client(client_id='C.abc', artifacts=['Custom.Collect.Companion.services_on_WIN11'])");
    expect(prog).not.toContain("-- persistence");   // comments stripped from the artifact source
  });

  it("reads the flow id leniently (FlowId / session_id fallbacks)", async () => {
    const a = collectRunner([], { FlowId: "F.aa" });
    expect((await new VelociraptorClient(cfg, a.runner).collectOnClient("C.1", "SELECT 1", "x")).flowId).toBe("F.aa");
    const b = collectRunner([], { session_id: "F.bb" });
    expect((await new VelociraptorClient(cfg, b.runner).collectOnClient("C.1", "SELECT 1", "x")).flowId).toBe("F.bb");
  });

  it("defaults the echoed hostname to the client id when none is given", async () => {
    const { runner } = collectRunner([]);
    expect((await new VelociraptorClient(cfg, runner).collectOnClient("C.1", "SELECT 1", "x")).hostname).toBe("C.1");
  });

  it("rejects an invalid client id", async () => {
    const { runner } = collectRunner([]);
    await expect(new VelociraptorClient(cfg, runner).collectOnClient("not-an-id", "SELECT 1", "x")).rejects.toThrow(/invalid Velociraptor client id/);
  });

  it("throws when the collection flow id is missing/invalid", async () => {
    const { runner } = collectRunner([], {});
    await expect(new VelociraptorClient(cfg, runner).collectOnClient("C.1", "SELECT 1", "x")).rejects.toThrow(/flow id/);
  });

  it("throws when the VQL is empty or only comments", async () => {
    const { runner } = collectRunner([]);
    await expect(new VelociraptorClient(cfg, runner).collectOnClient("C.1", "-- only a comment", "x")).rejects.toThrow(/No runnable VQL/);
  });
});

describe("VelociraptorClient.collectionResults", () => {
  it("reads a flow's rows via source(client_id, flow_id, artifact/source)", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ Name: "PSEXESVC", Pid: 42 }], raw: "" }; };
    const res = await new VelociraptorClient(cfg, runner).collectionResults("C.abc", "F.flow1", "Custom.Collect.Companion.x", ["Pivot0"]);
    expect(res.rows).toHaveLength(1);
    expect(program).toContain("source(client_id='C.abc', flow_id='F.flow1', artifact='Custom.Collect.Companion.x/Pivot0')");
  });

  it("chains multiple sources", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [], raw: "" }; };
    await new VelociraptorClient(cfg, runner).collectionResults("C.abc", "F.flow1", "Custom.Collect.Companion.x", ["Pivot0", "Pivot1"]);
    expect(program).toContain("chain(");
    expect(program).toContain("artifact='Custom.Collect.Companion.x/Pivot0'");
    expect(program).toContain("artifact='Custom.Collect.Companion.x/Pivot1'");
  });

  it("validates the client / flow / artifact ids", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    const c = new VelociraptorClient(cfg, runner);
    await expect(c.collectionResults("bad", "F.1", "Custom.X")).rejects.toThrow(/client id/);
    await expect(c.collectionResults("C.1", "bad", "Custom.X")).rejects.toThrow(/flow id/);
    await expect(c.collectionResults("C.1", "F.1", "bad name")).rejects.toThrow(/artifact name/);
  });
});

describe("VelociraptorClient.flowStatus", () => {
  it("surfaces an endpoint-side ERROR (status message) from the flow", async () => {
    let program = "";
    const runner: VqlRunner = async (s) => { program = s[0]; return { rows: [{ state: "ERROR", status: "handles: Unexpected arg process\n", total_collected_rows: 0 }], raw: "" }; };
    const st = await new VelociraptorClient(cfg, runner).flowStatus("C.abc", "F.flow1");
    expect(st.state).toBe("ERROR");
    expect(st.error).toBe("handles: Unexpected arg process");
    expect(program).toContain("FROM flows(client_id='C.abc') WHERE session_id='F.flow1'");
  });

  it("reports a FINISHED flow with no error", async () => {
    const runner: VqlRunner = async () => ({ rows: [{ state: "FINISHED", status: "", total_collected_rows: 3 }], raw: "" });
    const st = await new VelociraptorClient(cfg, runner).flowStatus("C.abc", "F.flow1");
    expect(st.state).toBe("FINISHED");
    expect(st.error).toBe("");
    expect(st.rows).toBe(3);
  });

  it("returns an empty state when the flow is not found", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    expect(await new VelociraptorClient(cfg, runner).flowStatus("C.abc", "F.flow1")).toEqual({ state: "", error: "", rows: 0 });
  });
});

describe("VelociraptorClient.huntStatus", () => {
  it("returns the hunt's state when found", async () => {
    let program = "";
    const runner: VqlRunner = async (s) => { program = s[0]; return { rows: [{ state: "RUNNING" }], raw: "" }; };
    const st = await new VelociraptorClient(cfg, runner).huntStatus("H.ABC123");
    expect(st).toEqual({ state: "RUNNING" });
    expect(program).toContain("FROM hunts() WHERE hunt_id='H.ABC123'");
    expect(program).toContain("SELECT state, expires");
  });

  it("returns null when the hunt is not found (deleted)", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    expect(await new VelociraptorClient(cfg, runner).huntStatus("H.GONE1")).toBeNull();
  });

  it("trims a missing/blank state field to an empty string, not undefined", async () => {
    const runner: VqlRunner = async () => ({ rows: [{}], raw: "" });
    expect(await new VelociraptorClient(cfg, runner).huntStatus("H.ABC123")).toEqual({ state: "" });
  });

  it("throws on an invalid hunt id", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    await expect(new VelociraptorClient(cfg, runner).huntStatus("not-a-hunt-id")).rejects.toThrow(/invalid hunt id/);
  });

  // Velociraptor's `hunts()` plugin reports `expires` as MICROSECONDS since the epoch (matching
  // create_time/start_time) — confirmed against a live server. Converted to an ISO string so callers
  // never have to know the unit.
  it("converts the hunt's microsecond expires field to an ISO string", async () => {
    const runner: VqlRunner = async () => ({ rows: [{ state: "STOPPED", expires: 1_783_586_781_000_000 }], raw: "" });
    const st = await new VelociraptorClient(cfg, runner).huntStatus("H.ABC123");
    expect(st).toEqual({ state: "STOPPED", expires: new Date(1_783_586_781_000).toISOString() });
  });

  it("omits expires when the field is missing or zero", async () => {
    const runner: VqlRunner = async () => ({ rows: [{ state: "RUNNING", expires: 0 }], raw: "" });
    expect(await new VelociraptorClient(cfg, runner).huntStatus("H.ABC123")).toEqual({ state: "RUNNING" });
  });
});

describe("VelociraptorClient.getHuntArtifacts", () => {
  it("returns the hunt's configured artifact list", async () => {
    let program = "";
    const runner: VqlRunner = async (s) => { program = s[0]; return { rows: [{ artifacts: ["Windows.NTFS.MFT", "Windows.Forensics.Usn"] }], raw: "" }; };
    const arts = await new VelociraptorClient(cfg, runner).getHuntArtifacts("H.ABC");
    expect(arts).toEqual(["Windows.NTFS.MFT", "Windows.Forensics.Usn"]);
    expect(program).toContain("FROM hunts() WHERE hunt_id='H.ABC'");
  });

  it("returns [] when the hunt is not found or has no artifacts", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    expect(await new VelociraptorClient(cfg, runner).getHuntArtifacts("H.ABC")).toEqual([]);
  });

  it("rejects an invalid hunt id", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    await expect(new VelociraptorClient(cfg, runner).getHuntArtifacts("not-a-hunt")).rejects.toThrow(/hunt id/i);
  });
});

describe("VelociraptorClient.getFlowInfo", () => {
  // A runner branching on the flows() query vs the clients() inventory query listClients() issues.
  function flowRunner(flowRow: Record<string, unknown>, clientRows: unknown[]): VqlRunner {
    return async (statements) => {
      const p = statements[0];
      if (p.includes("FROM flows(")) return { rows: [flowRow], raw: "" };
      if (p.includes("FROM clients(")) return { rows: clientRows, raw: "" };
      return { rows: [], raw: "" };
    };
  }

  it("returns the flow's artifacts (preferring artifacts_with_results) and resolves the host", async () => {
    const runner = flowRunner(
      { artifacts_with_results: ["Windows.NTFS.MFT"], req_artifacts: ["Windows.NTFS.MFT", "Windows.Forensics.Usn"] },
      [{ client_id: "C.dead", os_info: { hostname: "DESKTOP-01" } }],
    );
    const info = await new VelociraptorClient(cfg, runner).getFlowInfo("C.dead", "F.001");
    expect(info.artifacts).toEqual(["Windows.NTFS.MFT"]);
    expect(info.hostname).toBe("DESKTOP-01");
  });

  it("falls back to request.artifacts when nothing produced results", async () => {
    const runner = flowRunner(
      { artifacts_with_results: [], req_artifacts: ["Windows.NTFS.MFT"] },
      [{ client_id: "C.dead", os_info: { fqdn: "DESKTOP-01.corp.local" } }],
    );
    const info = await new VelociraptorClient(cfg, runner).getFlowInfo("C.dead", "F.001");
    expect(info.artifacts).toEqual(["Windows.NTFS.MFT"]);
    expect(info.hostname).toBe("DESKTOP-01.corp.local");   // fqdn fallback when no hostname
  });

  it("returns an empty hostname when the client id isn't in the inventory", async () => {
    const runner = flowRunner({ req_artifacts: ["Windows.NTFS.MFT"] }, []);
    const info = await new VelociraptorClient(cfg, runner).getFlowInfo("C.dead", "F.001");
    expect(info).toEqual({ artifacts: ["Windows.NTFS.MFT"], hostname: "" });
  });

  it("rejects an invalid client id", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    await expect(new VelociraptorClient(cfg, runner).getFlowInfo("not-an-id", "F.001")).rejects.toThrow(/client id/i);
  });

  it("rejects an invalid flow id", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    await expect(new VelociraptorClient(cfg, runner).getFlowInfo("C.dead", "not-a-flow")).rejects.toThrow(/flow id/i);
  });

  it("accepts a hunt-launched flow id (the .H suffix) and queries it verbatim", async () => {
    let queried = "";
    const runner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("FROM flows(")) { queried = p; return { rows: [{ artifacts_with_results: ["Windows.NTFS.MFT"] }], raw: "" }; }
      return { rows: [], raw: "" };
    };
    const info = await new VelociraptorClient(cfg, runner).getFlowInfo("C.9e5afcaf10536cd9", "F.D93M3ERL39HVE.H");
    expect(info.artifacts).toEqual(["Windows.NTFS.MFT"]);
    expect(queried).toContain("F.D93M3ERL39HVE.H");   // the ".H" reached the query, not a truncated id
  });
});

describe("VelociraptorClient.collectFromHost (live resolve)", () => {
  it("enumerates the fleet, matches the host (FQDN ⇄ short name), and collects on that client", async () => {
    // Case asset is an FQDN, but the client enrolled with the SHORT name — the old whole-FQDN search missed it.
    const { runner, programs } = collectRunner([{ client_id: "C.abc", os_info: { hostname: "win11" } }]);
    const res = await new VelociraptorClient(cfg, runner)
      .collectFromHost("WIN11.windomain.local", "SELECT Name FROM Artifact.Windows.System.Services()", "services on WIN11");
    expect(res.clientId).toBe("C.abc");
    expect(res.hostname).toBe("WIN11.windomain.local");
    // The resolve query enumerates clients() (no brittle host search); the host is matched in TS, never embedded.
    expect(programs[0]).toContain("FROM clients()");
    expect(programs[0]).not.toContain("search=");
    const collectProg = programs.find((p) => p.includes("collect_client(")) || "";
    expect(collectProg).toContain("collect_client(client_id='C.abc'");
  });

  it("throws when no client matches the host", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    await expect(new VelociraptorClient(cfg, runner).collectFromHost("GHOST", "SELECT 1", "x"))
      .rejects.toThrow(/No enrolled Velociraptor client matches host "GHOST"/);
  });

  it("throws when the VQL is empty or only comments (before resolving)", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    await expect(new VelociraptorClient(cfg, runner).collectFromHost("h", "-- only a comment", "x")).rejects.toThrow(/No runnable VQL/);
  });
});

describe("normalizeClientRow", () => {
  it("reads client_id + os_info casing-tolerantly", () => {
    expect(normalizeClientRow({ client_id: "C.a", os_info: { hostname: "h", fqdn: "h.d.local" }, last_seen_at: "t" }))
      .toEqual({ clientId: "C.a", hostname: "h", fqdn: "h.d.local", lastSeen: "t" });
    expect(normalizeClientRow({ ClientId: "C.b", OsInfo: { Hostname: "H", Fqdn: "H.D" } }))
      .toEqual({ clientId: "C.b", hostname: "H", fqdn: "H.D" });
  });

  it("returns null for a row with no valid client id", () => {
    expect(normalizeClientRow({ client_id: "nope", os_info: { hostname: "h" } })).toBeNull();
    expect(normalizeClientRow({})).toBeNull();
  });
});

describe("matchClient", () => {
  const recs: VeloClientRecord[] = [
    { clientId: "C.win11", hostname: "WIN11", fqdn: "WIN11.windomain.local" },
    { clientId: "C.web", hostname: "web01", fqdn: "web01.corp.local" },
  ];

  it("matches a short-name-enrolled client against an FQDN target (the #70 bug)", () => {
    expect(matchClient(recs, "WIN11.windomain.local")?.clientId).toBe("C.win11");
  });

  it("matches an FQDN-enrolled client against a short-name target", () => {
    expect(matchClient([{ clientId: "C.x", hostname: "", fqdn: "win11.windomain.local" }], "WIN11")?.clientId).toBe("C.x");
  });

  it("prefers an exact full match over a first-label match", () => {
    const two: VeloClientRecord[] = [
      { clientId: "C.short", hostname: "web01", fqdn: "" },              // short-label match
      { clientId: "C.full", hostname: "", fqdn: "web01.corp.local" },   // exact FQDN match
    ];
    expect(matchClient(two, "web01.corp.local")?.clientId).toBe("C.full");
  });

  it("skips malformed ids and returns undefined when nothing matches", () => {
    expect(matchClient([{ clientId: "bad", hostname: "pc1", fqdn: "" }], "pc1")).toBeUndefined();
    expect(matchClient(recs, "unknown-host")).toBeUndefined();
    expect(matchClient([], "pc1")).toBeUndefined();
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
  it("queries artifact_definitions and returns name+description without the row cap", async () => {
    let program = "";
    const rows = Array.from({ length: 10 }, (_, i) => ({ name: `Windows.Test.A${i}`, description: `d${i}`, type: "CLIENT" }));
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows, raw: "" }; };
    const out = await new VelociraptorClient(cfg, runner).listClientArtifacts();   // cfg.maxRows = 3
    expect(program).toContain("artifact_definitions()");
    expect(out).toHaveLength(10);   // metadata, NOT capped at maxRows
    expect(out[0]).toEqual({ name: "Windows.Test.A0", description: "d0", parameters: [] });
  });

  it("filters the type in TS — version-tolerant of casing/spacing (CLIENT_EVENT / Client Event / client-event)", async () => {
    const rows = [
      { name: "Windows.System.Pslist", description: "p", type: "CLIENT" },
      { name: "Windows.Events.ProcessCreation", description: "e1", type: "CLIENT_EVENT" },
      { name: "Windows.Events.DNSQueries", description: "e2", type: "Client Event" },   // spaced
      { name: "Windows.Events.ServiceCreation", description: "e3", type: "client-event" }, // hyphen
      { name: "Server.Foo", description: "s", type: "SERVER_EVENT" },
    ];
    const runner: VqlRunner = async () => ({ rows, raw: "" });
    const client = new VelociraptorClient(cfg, runner);
    expect((await client.listClientArtifacts("client_event")).map((a) => a.name))
      .toEqual(["Windows.Events.ProcessCreation", "Windows.Events.DNSQueries", "Windows.Events.ServiceCreation"]);
    expect((await client.listClientArtifacts("client")).map((a) => a.name)).toEqual(["Windows.System.Pslist"]);
  });
});

describe("listClientArtifacts — parameter metadata", () => {
  it("returns each artifact's parameters with lowercased types", async () => {
    const runner: VqlRunner = async () => ({ rows: [{
      name: "Windows.EventLogs.Evtx", description: "Event logs", type: "CLIENT",
      parameters: [
        { name: "DateAfter", type: "timestamp", description: "" },
        { name: "DateBefore", type: "Timestamp" },
        { name: "EvtxGlob", type: "string" },
      ],
    }], raw: "" });
    const arts = await new VelociraptorClient(cfg, runner).listClientArtifacts();
    expect(arts[0].parameters).toEqual([
      { name: "DateAfter", type: "timestamp" },
      { name: "DateBefore", type: "timestamp" },
      { name: "EvtxGlob", type: "string" },
    ]);
  });

  it("tolerates a server that reports no parameter metadata", async () => {
    const runner: VqlRunner = async () => ({ rows: [
      { name: "Windows.NTFS.MFT", description: "MFT", type: "CLIENT" },                  // key absent
      { name: "Windows.Sys.Users", description: "Users", type: "CLIENT", parameters: null },
      { name: "Windows.Sys.Programs", description: "Programs", type: "CLIENT", parameters: "junk" },
    ], raw: "" });
    const arts = await new VelociraptorClient(cfg, runner).listClientArtifacts();
    expect(arts.map((a) => a.parameters)).toEqual([[], [], []]);
  });
});

describe("parseArtifactParams", () => {
  it("keeps only the valid entries, in order, from a mixed-validity array", () => {
    const out = parseArtifactParams([
      { name: "DateAfter", type: "Timestamp" },  // valid, type lowercased
      { name: "EvtxGlob" },                      // valid, no type -> key omitted
      { type: "string" },                        // missing name -> dropped
      null,                                       // null element -> dropped
      "DateBefore",                               // bare string element -> dropped
      [{ name: "Nested" }],                       // nested array element -> dropped
    ]);
    expect(out).toEqual([
      { name: "DateAfter", type: "timestamp" },
      { name: "EvtxGlob" },
    ]);
    expect(out[1]).not.toHaveProperty("type");
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
    expect(program).toContain("expires=now() + 3600");   // default one-hour expiry
  });

  it("uses a supplied relative expiry (seconds)", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ Hunt: { HuntId: "H.BEXP", state: "RUNNING" } }], raw: "" }; };
    await new VelociraptorClient(cfg, runner).launchArtifactHunt(["Windows.System.Pslist"], "x", {}, { expirySeconds: 86_400 });
    expect(program).toContain("expires=now() + 86400");   // one day
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

  it("is resilient: an artifact whose fetch fails (oversized) is skipped WITH its reason, the rest still import", async () => {
    const runner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("Hayabusa")) throw new Error("output exceeded 52428800 bytes");
      return { rows: [{ Name: "ok" }], raw: "" };
    };
    const { results, skipped } = await new VelociraptorClient(cfg, runner).huntResultsByArtifact("H.ABC123", ["Windows.Hayabusa.Rules", "Windows.System.Pslist"]);
    expect(skipped).toEqual([{ name: "Windows.Hayabusa.Rules", error: "output exceeded 52428800 bytes" }]);
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

  it("reads a fleet-hunt artifact's NAMED sources as artifact/source (#157 — else 0 rows / false 'no evidence')", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ a: 1 }], raw: "" }; };
    const { results } = await new VelociraptorClient(cfg, runner).huntResultsByArtifact(
      "H.OK1", ["Custom.Hunt.Companion.x"], undefined, { "Custom.Hunt.Companion.x": ["Pivot0"] });
    expect(program).toContain("artifact='Custom.Hunt.Companion.x/Pivot0'");
    expect(results["Custom.Hunt.Companion.x"]).toHaveLength(1);
  });
});

describe("retryTransientSpawn", () => {
  const noSleep = async () => {};
  const launchErr = (code: string) => Object.assign(new Error(`spawn ${code}`), { spawnCode: code });

  it("retries a transient spawn lock (EPERM) then succeeds", async () => {
    let calls = 0;
    const out = await retryTransientSpawn(async () => {
      calls++;
      if (calls < 3) throw launchErr("EPERM");
      return "ok";
    }, { sleep: noSleep });
    expect(out).toBe("ok");
    expect(calls).toBe(3);
  });

  it("does NOT retry a query failure (no spawnCode)", async () => {
    let calls = 0;
    await expect(retryTransientSpawn(async () => { calls++; throw new Error("velociraptor exited with code 1"); }, { sleep: noSleep }))
      .rejects.toThrow(/exited with code 1/);
    expect(calls).toBe(1);
  });

  it("does NOT retry a non-transient launch failure (ENOENT — wrong binary path)", async () => {
    let calls = 0;
    await expect(retryTransientSpawn(async () => { calls++; throw launchErr("ENOENT"); }, { sleep: noSleep }))
      .rejects.toThrow(/ENOENT/);
    expect(calls).toBe(1);
  });

  it("rethrows the transient error after exhausting the retry budget", async () => {
    let calls = 0;
    await expect(retryTransientSpawn(async () => { calls++; throw launchErr("EPERM"); }, { retries: 2, sleep: noSleep }))
      .rejects.toThrow(/EPERM/);
    expect(calls).toBe(3);   // initial + 2 retries
  });
});

describe("spawnErrorMessage", () => {
  it("adds AV/EDR + GUI guidance for a persistent EPERM/EACCES block", () => {
    const m = spawnErrorMessage("velociraptor.exe", { message: "spawn EPERM", code: "EPERM" });
    expect(m).toContain('velociraptor.exe');
    expect(m).toContain("spawn EPERM");
    expect(m).toMatch(/antivirus\/EDR/i);
    expect(m).toMatch(/lsass\.dmp/);
    expect(m).toMatch(/Velociraptor GUI/);
    expect(spawnErrorMessage("v", { message: "x", code: "EACCES" })).toMatch(/exclusion/);
  });

  it("stays terse for other codes (e.g. ENOENT — wrong path)", () => {
    const m = spawnErrorMessage("nope.exe", { message: "spawn ENOENT", code: "ENOENT" });
    expect(m).toBe('Failed to run velociraptor binary "nope.exe": spawn ENOENT');
  });
});

describe("translateVelociraptorError", () => {
  it("points a gRPC message-size failure at the CLIENT-side api_client.yaml's max_grpc_recv_size field, not a CLI flag or the server config", () => {
    const m = translateVelociraptorError("velociraptor-v0.76.5-windows-amd64.exe: error: query: rpc error: code = ResourceExhausted desc = grpc: received message larger than max (18006256 vs. 4194304)");
    expect(m).toContain("received message larger than max");
    expect(m).toContain("max_grpc_recv_size");
    expect(m).toContain("api_client.yaml");
    expect(m).not.toContain("--max_message_size");   // that flag doesn't exist — must never be suggested again
    expect(m).not.toContain("Frontend.resources.max_upload_size");   // wrong setting — a different data path (server config, not this gRPC connection)
  });

  it("passes through any other stderr unchanged", () => {
    expect(translateVelociraptorError("unknown long flag '--max_message_size', try --help")).toBe("unknown long flag '--max_message_size', try --help");
    expect(translateVelociraptorError("")).toBe("");
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

  it("broadens the upload filter beyond .json to common text-report extensions", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [], raw: "" }; };
    await new VelociraptorClient(cfg, runner).huntUploads("H.UP3");
    expect(program).toContain("(json|jsonl|ndjson|csv|txt|log)");
    expect(program).not.toContain("\\.json$'");   // the old json-only filter is gone
  });
});

describe("VelociraptorClient.flowUploads", () => {
  it("reads one flow's upload content and substitutes both client id and flow id into the VQL", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => {
      program = statements[0];
      return { rows: [
        { ClientId: "C.dead", Path: "C:/t/report.json", Name: "report.json", Content: '{"a":1}' },
        { ClientId: "C.dead", Path: "C:/t/empty.json", Name: "empty.json", Content: "" },
      ], raw: "" };
    };
    const ups = await new VelociraptorClient(cfg, runner).flowUploads("C.dead", "F.CFF001");
    expect(program).toContain("client_id='C.dead'");
    expect(program).toContain("flow_id='F.CFF001'");
    expect(program).not.toContain("__CLIENT_ID__");
    expect(program).not.toContain("__FLOW_ID__");
    expect(ups).toHaveLength(1);   // the empty-content row is dropped
    expect(ups[0]).toEqual({ name: "report.json", clientId: "C.dead", content: '{"a":1}' });
  });

  it("uses the configured override VQL (DFIR_VELOCIRAPTOR_FLOW_UPLOAD_VQL) when set", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [], raw: "" }; };
    await new VelociraptorClient(
      { ...cfg, flowUploadVql: "SELECT * FROM custom(client='__CLIENT_ID__', flow='__FLOW_ID__')" },
      runner,
    ).flowUploads("C.dead", "F.CFF001");
    expect(program).toBe("SELECT * FROM custom(client='C.dead', flow='F.CFF001')");
  });

  it("rejects a malformed client id or flow id (no VQL-string injection)", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    await expect(new VelociraptorClient(cfg, runner).flowUploads("bad id", "F.CFF001")).rejects.toThrow(/invalid client id/);
    await expect(new VelociraptorClient(cfg, runner).flowUploads("C.dead", "bad id")).rejects.toThrow(/invalid flow id/);
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

describe("VelociraptorClient.monitorResults", () => {
  it("reads ONE client's monitoring set via source() with the window", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ _ts: 1500 }], raw: "" }; };
    const res = await new VelociraptorClient(cfg, runner).monitorResults("C.abc", "Windows.Events.ProcessCreation", 1000, 2000);
    expect(program).toContain("source(client_id='C.abc'");
    expect(program).toContain("artifact='Windows.Events.ProcessCreation'");
    expect(program).toContain("start_time=1000");
    expect(program).toContain("end_time=2000");
    expect(res.rows).toHaveLength(1);
  });

  it("reads ALL clients via the foreach(clients()) VQL when given the '*' sentinel (no client id injected)", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [{ _ts: 1, ClientId: "C.a" }, { _ts: 2, ClientId: "C.b" }], raw: "" }; };
    const res = await new VelociraptorClient(cfg, runner).monitorResults("*", "Windows.Events.ProcessCreation", 1000, 2000);
    expect(program).toContain("clients()");
    expect(program).toContain("artifact='Windows.Events.ProcessCreation'");
    expect(program).not.toContain("client_id='*'");   // sentinel never lands in the literal
    expect(res.rows).toHaveLength(2);
  });

  it("rejects an invalid (non-sentinel) client id", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    await expect(new VelociraptorClient(cfg, runner).monitorResults("bad", "A.B", 0, 1)).rejects.toThrow(/invalid client id/);
  });

  it("honors the DFIR_VELOCIRAPTOR_MONITOR_ALL_VQL override", async () => {
    let program = "";
    const runner: VqlRunner = async (statements) => { program = statements[0]; return { rows: [], raw: "" }; };
    await new VelociraptorClient({ ...cfg, monitorAllVql: "CUSTOM __ARTIFACT__ __START__ __END__ __LIMIT__" }, runner)
      .monitorResults("*", "A.B", 5, 9);
    expect(program).toBe("CUSTOM A.B 5 9 4");   // maxRows(3)+1
  });
});

describe("VelociraptorClient.listMonitoredArtifacts", () => {
  it("returns de-duplicated artifact names from the monitoring state", async () => {
    const runner: VqlRunner = async () => ({ rows: [
      { artifact: "Windows.Events.ProcessCreation" },
      { artifact: "Windows.Events.DNSQueries" },
      { artifact: "Windows.Events.ProcessCreation" },   // dup
      { artifact: "" },                                  // dropped
      { artifact: "bad name!" },                         // invalid → dropped
    ], raw: "" });
    const out = await new VelociraptorClient(cfg, runner).listMonitoredArtifacts();
    expect(out).toEqual(["Windows.Events.ProcessCreation", "Windows.Events.DNSQueries"]);
  });

  it("tolerates bare-string and Name-keyed rows", async () => {
    const runner: VqlRunner = async () => ({ rows: ["Windows.Events.DNSQueries", { Name: "Generic.Client.Stats" }], raw: "" });
    const out = await new VelociraptorClient(cfg, runner).listMonitoredArtifacts();
    expect(out).toEqual(["Windows.Events.DNSQueries", "Generic.Client.Stats"]);
  });

  it("returns [] (no throw) when nothing is configured", async () => {
    const runner: VqlRunner = async () => ({ rows: [], raw: "" });
    expect(await new VelociraptorClient(cfg, runner).listMonitoredArtifacts()).toEqual([]);
  });

  it("walks a real GetClientMonitoringState() proto row (the default VQL shape)", async () => {
    // One row, the whole ClientEventTable proto under `State` — artifacts.artifacts + specs + label_events.
    const runner: VqlRunner = async () => ({ rows: [{ State: {
      artifacts: {
        artifacts: ["Generic.Client.Stats", "Windows.Events.ProcessCreation"],
        specs: [{ artifact: "Generic.Client.Stats" }, { artifact: "Windows.Events.DNSQueries" }],
      },
      label_events: [
        { label: "servers", artifacts: { artifacts: ["Windows.Events.ServiceCreation"] } },
      ],
    } }], raw: "" });
    const out = await new VelociraptorClient(cfg, runner).listMonitoredArtifacts();
    expect(out).toEqual([
      "Generic.Client.Stats",
      "Windows.Events.ProcessCreation",
      "Windows.Events.DNSQueries",
      "Windows.Events.ServiceCreation",
    ]);
  });
});

describe("extractMonitoredArtifacts", () => {
  it("handles the bare (unwrapped) ClientEventTable proto", () => {
    expect(extractMonitoredArtifacts([{ artifacts: { artifacts: ["A.B", "C.D"] } }])).toEqual(["A.B", "C.D"]);
  });
  it("tolerates PascalCase proto fields", () => {
    expect(extractMonitoredArtifacts([{ State: { Artifacts: { Artifacts: ["A.B"], Specs: [{ Artifact: "C.D" }] } } }])).toEqual(["A.B", "C.D"]);
  });
  it("handles override shapes (bare strings / { artifact })", () => {
    expect(extractMonitoredArtifacts(["A.B", { artifact: "C.D" }, { Name: "E.F" }])).toEqual(["A.B", "C.D", "E.F"]);
  });
  it("dedupes across the global table and label tables, dropping invalid names", () => {
    expect(extractMonitoredArtifacts([{ State: {
      artifacts: { artifacts: ["A.B", "bad name!", "A.B"] },
      label_events: [{ artifacts: { artifacts: ["A.B", "C.D"] } }],
    } }])).toEqual(["A.B", "C.D"]);
  });
  it("returns [] for empty / junk input", () => {
    expect(extractMonitoredArtifacts([])).toEqual([]);
    expect(extractMonitoredArtifacts([null, 5, { nope: 1 }])).toEqual([]);
  });
});
