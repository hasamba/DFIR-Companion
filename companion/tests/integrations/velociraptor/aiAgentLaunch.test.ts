// AI Agent Forensics (#2690): launch on explicit endpoints, preflight, and the manifest-only upload
// policy. The Velociraptor API is a recording mock; nothing here touches a server.
import { describe, expect, it } from "vitest";
import { loadAiAgentRuleSet } from "../../../src/analysis/aiAgentRuleSet.js";
import {
  buildAiAgentArtifact,
  AI_AGENT_MAX_PROGRAM_CHARS,
} from "../../../src/integrations/velociraptor/aiAgentArtifact.js";
import {
  AiAgentLaunchError,
  launchAiAgentRun,
  type AiAgentLaunchClient,
} from "../../../src/integrations/velociraptor/aiAgentLaunch.js";
import { preflightAiAgentRun } from "../../../src/integrations/velociraptor/aiAgentPreflight.js";
import {
  VelociraptorClient,
  type VqlRunner,
  type VeloArtifactInfo,
} from "../../../src/integrations/velociraptor/velociraptorApi.js";
import {
  ExternalRetentionError,
  readUploadManifest,
} from "../../../src/integrations/velociraptor/uploadVql.js";

const bundle = buildAiAgentArtifact(loadAiAgentRuleSet());
const input = (clientIds: string[], preserve = true) => ({
  bundle,
  clientIds,
  preserve,
  uploadMaxBytes: 50 * 1024 * 1024,
  description: "AI Agent Forensics (sensitive)",
});

function mockClient(
  opts: { refuseSet?: boolean; refuseReason?: string; addFails?: string[]; noHunt?: boolean } = {},
) {
  const programs: string[] = [];
  const client: AiAgentLaunchClient = {
    huntGuiUrlFor: (h) => `https://velo.example/app/index.html#/hunts/${h}`,
    async runProgram(p) {
      programs.push(p);
      if (p.includes("artifact_set"))
        return opts.refuseSet
          ? { rows: [], reason: opts.refuseReason ?? "PermissionDenied" }
          : { rows: [{ Set: {} }], reason: "" };
      if (p.includes("hunt("))
        return opts.noHunt
          ? { rows: [], reason: "x" }
          : { rows: [{ Hunt: { HuntId: "H.AI1" } }], reason: "" };
      if (p.includes("hunt_add")) {
        const id = /client_id='([^']+)'/.exec(p)![1];
        return opts.addFails?.includes(id)
          ? { rows: [], reason: "client unknown" }
          : { rows: [{ Added: id }], reason: "" };
      }
      return { rows: [{}], reason: "" };
    },
  };
  return { client, programs };
}

describe("AI Agent Forensics launch", () => {
  it("never targets the fleet: an empty selection fails before any call", async () => {
    const { client, programs } = mockClient();
    await expect(launchAiAgentRun(client, input([]))).rejects.toThrow(/never targets the fleet/);
    await expect(launchAiAgentRun(client, input(["  "]))).rejects.toThrow(AiAgentLaunchError);
    expect(programs).toEqual([]);
  });

  it("refuses an invalid client id before any call", async () => {
    const { client, programs } = mockClient();
    await expect(launchAiAgentRun(client, input(["C.1' OR 1"]))).rejects.toThrow(
      /invalid Velociraptor client id/,
    );
    expect(programs).toEqual([]);
  });

  it("sets every definition, then a PAUSED hunt with the triage spec, then adds exactly the chosen clients", async () => {
    const { client, programs } = mockClient();
    const r = await launchAiAgentRun(client, input(["C.aaa", "C.bbb", "C.aaa"]));
    const sets = programs.filter((p) => p.includes("artifact_set"));
    expect(sets).toHaveLength(bundle.parts.length + bundle.artifacts.length);
    const hunt = programs.find((p) => p.includes("hunt("))!;
    expect(hunt).toContain("pause=TRUE");
    expect(hunt).toContain("timeout=7200");
    expect(hunt).toContain("`Windows.Triage.Targets`=dict(AICodingAgents='Y', MaxFileSize='52428800')");
    expect(hunt).not.toContain("include_labels");
    expect(programs.indexOf(hunt)).toBeGreaterThan(programs.indexOf(sets[sets.length - 1]));
    expect(programs.filter((p) => p.includes("hunt_add"))).toHaveLength(2);
    expect(r).toMatchObject({ huntId: "H.AI1", added: ["C.aaa", "C.bbb"], failed: [] });
    expect(r.artifacts).toContain("Windows.Triage.Targets");
    for (const p of programs) expect(p.length).toBeLessThan(AI_AGENT_MAX_PROGRAM_CHARS);
  });

  it("leaves preservation out when the server has no AICodingAgents rule", async () => {
    const { client, programs } = mockClient();
    const r = await launchAiAgentRun(client, input(["C.aaa"], false));
    expect(programs.find((p) => p.includes("hunt("))).not.toContain("Windows.Triage.Targets");
    expect(r.artifacts).not.toContain("Windows.Triage.Targets");
  });

  it("reports clients that could not be added by name", async () => {
    const { client } = mockClient({ addFails: ["C.bbb"] });
    const r = await launchAiAgentRun(client, input(["C.aaa", "C.bbb"]));
    expect(r.added).toEqual(["C.aaa"]);
    expect(r.failed).toEqual([{ clientId: "C.bbb", error: "client unknown" }]);
  });

  it("stops the hunt and fails when no client could be added", async () => {
    const { client, programs } = mockClient({ addFails: ["C.aaa"] });
    await expect(launchAiAgentRun(client, input(["C.aaa"]))).rejects.toThrow(/no endpoint could be added/);
    expect(programs.some((p) => p.includes("hunt_update(hunt_id='H.AI1', state='stop')"))).toBe(true);
  });

  it("names the missing permission when artifact_set is refused, and launches nothing", async () => {
    const { client, programs } = mockClient({ refuseSet: true });
    await expect(launchAiAgentRun(client, input(["C.aaa"]))).rejects.toThrow(/ARTIFACT_WRITER/);
    expect(programs.some((p) => p.includes("hunt("))).toBe(false);
  });

  it("passes on Velociraptor's own reason without blaming a permission it did not name", async () => {
    const reason = "ERROR:artifact_set: Invalid artifact name.";
    const { client } = mockClient({ refuseSet: true, refuseReason: reason });
    const err = await launchAiAgentRun(client, input(["C.aaa"])).catch((e: Error) => e);
    expect(String(err)).toContain("Invalid artifact name");
    expect(String(err)).not.toMatch(/ARTIFACT_WRITER/);
  });

  it("fails clearly when the server returns no hunt id", async () => {
    const { client } = mockClient({ noHunt: true });
    await expect(launchAiAgentRun(client, input(["C.aaa"]))).rejects.toThrow(/START_HUNT/);
  });
});

describe("AI Agent Forensics preflight", () => {
  const triage = (params: string[]): VeloArtifactInfo => ({
    name: "Windows.Triage.Targets",
    description: "",
    parameters: params.map((name) => ({ name })),
  });
  const eps = [
    { clientId: "C.w1", hostname: "DEV-WS-014", os: "windows" },
    { clientId: "C.l1", hostname: "BUILD-LNX", os: "linux" },
  ];

  it("cannot run with no Windows endpoint", async () => {
    const p = await preflightAiAgentRun([eps[1]], async () => [triage(["AICodingAgents"])]);
    expect(p.error).toBe("no Windows endpoint is selected");
  });

  it("preserves when the triage target has the AICodingAgents rule and drops non-Windows endpoints", async () => {
    const p = await preflightAiAgentRun(eps, async () => [triage(["AICodingAgents", "KapeTriage"])]);
    expect(p).toMatchObject({ clientIds: ["C.w1"], preserve: true });
    expect(p.skipped[0]).toMatchObject({ clientId: "C.l1" });
  });

  it("runs detection without preservation on an older triage release, and says so", async () => {
    const p = await preflightAiAgentRun([eps[0]], async () => [triage(["KapeTriage"])]);
    expect(p.preserve).toBe(false);
    expect(p.warnings[0]).toContain("artifacts not preserved");
  });

  it("never blocks on a catalog read failure", async () => {
    const p = await preflightAiAgentRun([eps[0]], async () => {
      throw new Error("timeout");
    });
    expect(p.error).toBeUndefined();
    expect(p.warnings[0]).toContain("timeout");
  });
});

describe("AI Agent Forensics: manifest-only uploads", () => {
  const cfg = {
    apiConfigPath: "/tmp/api.config.yaml",
    binary: "velociraptor",
    timeoutMs: 5000,
    maxRows: 3,
    maxOutputBytes: 1 << 20,
  };
  // A runner that FAILS THE TEST if any upload content is read, and says the hunt/flow is an AI run.
  const aiRunner: VqlRunner = async (s) => {
    const p = s[0];
    if (/read_file\(/.test(p)) throw new Error("upload CONTENT was read");
    if (/FROM hunts\(\)|FROM flows\(/.test(p))
      return { rows: [{ artifacts: ["Custom.DFIRCompanion.AIAgentForensics.0123456789abcdef"] }], raw: "" };
    return { rows: [], raw: "" };
  };

  it("refuses the hunt upload read for an AI Agent Forensics run, before any content VQL", async () => {
    const c = new VelociraptorClient(cfg, aiRunner);
    await expect(c.huntUploads("H.AI1")).rejects.toBeInstanceOf(ExternalRetentionError);
  });

  it("refuses it with a DFIR_VELOCIRAPTOR_UPLOAD_VQL override too", async () => {
    const c = new VelociraptorClient(
      {
        ...cfg,
        uploadVql: "SELECT read_file(filename='x') AS Content FROM hunt_flows(hunt_id='__HUNT_ID__')",
      },
      aiRunner,
    );
    await expect(c.huntUploads("H.AI1")).rejects.toBeInstanceOf(ExternalRetentionError);
  });

  it("refuses the single-collection (flow) variant", async () => {
    const c = new VelociraptorClient(cfg, aiRunner);
    await expect(c.flowUploads("C.aaa", "F.123.H")).rejects.toBeInstanceOf(ExternalRetentionError);
  });

  it("fails closed when it cannot tell whether the hunt is an AI Agent Forensics run", async () => {
    const runner: VqlRunner = async (q) => {
      if (/FROM hunts\(\)/.test(q[0])) throw new Error("hunts() unavailable");
      throw new Error("upload CONTENT was read");
    };
    await expect(new VelociraptorClient(cfg, runner).huntUploads("H.X1")).rejects.toThrow(
      /could not confirm/,
    );
  });

  // A probe that runs but proves nothing — no row, a logged VQL error, a row without its artifact
  // list — must never let the content-reading VQL run (fails closed).
  const contentGuard =
    (probeRows: unknown[], stderr = ""): VqlRunner =>
    async (q) => {
      if (/read_file\(/.test(q[0])) throw new Error("upload CONTENT was read");
      return { rows: probeRows, raw: "", stderr };
    };
  const loggedError = "[ERROR] 2026-11-19T10:00:00Z hunts: PermissionDenied: user lacks READ_RESULTS\n";
  it.each([
    ["an empty probe", [], ""],
    ["a logged permission error", [{ artifacts: ["Generic.Scanner.ThorZIP"] }], loggedError],
    ["a row without its artifact list", [{ state: "FINISHED" }], ""],
  ])("refuses the hunt upload read on %s", async (_label, rows, stderr) => {
    await expect(new VelociraptorClient(cfg, contentGuard(rows, stderr)).huntUploads("H.X2")).rejects.toThrow(
      ExternalRetentionError,
    );
  });
  it.each([
    ["an empty probe", [], ""],
    ["a logged permission error", [{ request: { artifacts: ["Generic.Scanner.ThorZIP"] } }], loggedError],
    ["a row without its artifact list", [{ state: "FINISHED" }], ""],
  ])("refuses the flow upload read on %s", async (_label, rows, stderr) => {
    await expect(
      new VelociraptorClient(cfg, contentGuard(rows, stderr)).flowUploads("C.aaa", "F.1"),
    ).rejects.toThrow(ExternalRetentionError);
  });
  it("reads a flow's uploads once its artifact list proves it is not an AI Agent Forensics run", async () => {
    const runner: VqlRunner = async (s) =>
      /FROM flows\(/.test(s[0])
        ? { rows: [{ request: { artifacts: ["Generic.Scanner.ThorZIP"] } }], raw: "" }
        : { rows: [{ Name: "thor.json", ClientId: "C.aaa", Content: "{}" }], raw: "" };
    expect(await new VelociraptorClient(cfg, runner).flowUploads("C.aaa", "F.1")).toHaveLength(1);
  });

  it("still reads uploads for any other hunt", async () => {
    const runner: VqlRunner = async (s) =>
      /FROM hunts\(\)/.test(s[0])
        ? { rows: [{ artifacts: ["Generic.Scanner.ThorZIP"] }], raw: "" }
        : { rows: [{ Name: "thor.json", ClientId: "C.1", Content: "{}" }], raw: "" };
    expect(await new VelociraptorClient(cfg, runner).huntUploads("H.T1")).toHaveLength(1);
  });

  it("reads the manifest without content: path, size, server-side hash", async () => {
    let program = "";
    const m = await readUploadManifest(
      {
        async runProgram(p) {
          program = p;
          return {
            rows: [
              {
                ClientId: "C.1",
                FlowId: "F.1",
                Path: "/uploads/auto/C%3A/Users/dev/.claude.json",
                Size: 120,
                SHA256: "ab",
              },
            ],
            reason: "",
          };
        },
      },
      "H.AI1",
    );
    expect(program).not.toContain("read_file");
    expect(program).toContain("hunt_flows(hunt_id='H.AI1')");
    expect(m).toEqual([
      {
        clientId: "C.1",
        flowId: "F.1",
        path: "/uploads/auto/C%3A/Users/dev/.claude.json",
        size: 120,
        sha256: "ab",
      },
    ]);
    await expect(
      readUploadManifest({ runProgram: async () => ({ rows: [], reason: "" }) }, "H.x'"),
    ).rejects.toThrow();
  });
});
