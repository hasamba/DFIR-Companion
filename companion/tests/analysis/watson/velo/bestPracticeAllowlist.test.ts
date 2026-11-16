import { describe, expect, it } from "vitest";
import { checkLaunch } from "../../../../src/analysis/ai/watson/velo/launchCheck.js";
import { classifyReason, splitReasons } from "../../../../src/analysis/ai/watson/velo/vqlRiskClass.js";
import { vqlAllowed } from "../../../../src/analysis/ai/watson/velo/vqlAllowed.js";
import { ALLOWED_ARTIFACTS } from "../../../../src/analysis/ai/watson/velo/vqlAllowlist.js";
import { BUILT_IN_BUNDLES } from "../../../../src/analysis/artifactBundleStore.js";
import {
  matchClient,
  type VeloClientRecord,
} from "../../../../src/integrations/velociraptor/clientInventory.js";

// User decision 2026-11-15: every artifact of the built-in Best Practice bundle is safe for Watson.
// The slow full-disk "Big Hogs" bundle is not. Every other rule (arguments, accessors, hidden
// characters, modes) still applies to these artifacts.

const bundle = (id: string): readonly string[] => BUILT_IN_BUNDLES.find((b) => b.id === id)?.artifacts ?? [];
const has = (name: string): boolean => ALLOWED_ARTIFACTS.some((a) => a.toLowerCase() === name.toLowerCase());

const inventory: VeloClientRecord[] = [
  { clientId: "C.alpha1", hostname: "WKS-ALPHA", fqdn: "wks-alpha.corp.example.com" },
];
const ctx = { inventory, deployed: new Set<string>(), matchClient };
const collect = (vql: string) => checkLaunch({ vql, mode: "collection", hostname: "wks-alpha" }, ctx);

describe("Best Practice artifacts on Watson's safe list", () => {
  it("lists every Best Practice artifact", () => {
    const bp = bundle("best-practice");
    expect(bp.length).toBeGreaterThan(30);
    expect(bp.filter((a) => !has(a))).toEqual([]);
  });

  it("keeps the Big Hogs artifacts off the list", () => {
    const hogs = bundle("best-practice-big-hogs");
    expect(hogs.length).toBeGreaterThan(0);
    expect(hogs.filter((a) => has(a))).toEqual([]);
  });

  it("keeps the original reviewed artifacts", () => {
    for (const a of [
      "Windows.System.Pslist",
      "Windows.Search.FileFinder",
      "Generic.Client.Info",
      "Linux.Sys.Pslist",
    ])
      expect(has(a), a).toBe(true);
  });

  it.each(["Windows.Hayabusa.Rules", "DetectRaptor.Windows.Detection.Powershell.PSReadline"])(
    "%s is no longer risky and passes the launch check with no arguments",
    (name) => {
      const vql = `SELECT * FROM Artifact.${name}()`;
      expect(vqlAllowed(vql)).toEqual({ ok: true });
      const r = collect(vql);
      expect(r).toMatchObject({ ok: true, mode: "collection", clientHost: "WKS-ALPHA" });
      expect(r.ok && r.risky).toBeFalsy();
    },
  );

  it("an artifact outside the list is still risky", () => {
    const r = vqlAllowed("SELECT * FROM Artifact.DetectRaptor.Windows.Detection.MFT()");
    expect(r.ok).toBe(false);
    const reasons = r.ok ? [] : r.reasons;
    expect(splitReasons(reasons)).toEqual({ hard: [], risky: reasons });
    expect(collect("SELECT * FROM Artifact.DetectRaptor.Windows.Detection.MFT()").ok).toBe(false);
  });

  it("an upload argument on a newly allowed artifact is still refused", () => {
    const r = vqlAllowed("SELECT * FROM Artifact.Windows.Hayabusa.Rules(UploadResults='Y')");
    expect(r.ok).toBe(false);
    const reasons = r.ok ? [] : r.reasons;
    expect(reasons).toContain("argument UploadResults is refused (uploads, dumps and lambdas)");
    expect(reasons.every((x) => classifyReason(x) === "risky")).toBe(true);
    expect(collect("SELECT * FROM Artifact.Windows.Hayabusa.Rules(UploadResults='Y')").ok).toBe(false);
  });
});

// Codex branch review #1 (controller ruling 2026-11-15): a Best Practice artifact is safe only in its
// default run, `Artifact.<Name>()` with no arguments. Any argument makes the query RISKY (the analyst
// can still approve it; Auto never launches it). On the six reviewed artifacts (none fetches a tool),
// only a Tool_* override is RISKY (amended ruling); their other arguments keep their old rules.
const auto = (vql: string) =>
  checkLaunch({ vql, mode: "collection", hostname: "wks-alpha" }, { ...ctx, allowRisky: true });

function expectRiskyOnly(vql: string): string[] {
  const r = vqlAllowed(vql);
  expect(r.ok, vql).toBe(false);
  const reasons = r.ok ? [] : r.reasons;
  expect(splitReasons(reasons), vql).toEqual({ hard: [], risky: reasons });
  expect(collect(vql).ok, vql).toBe(false);
  const a = auto(vql);
  expect(a.ok && a.risky && a.risky.length > 0, vql).toBe(true);
  return reasons;
}

describe("Best Practice artifacts: only the default run is safe", () => {
  it("Autoruns with a tool file name and hash override is risky, not safe and not refused", () => {
    const reasons = expectRiskyOnly(
      "SELECT * FROM Artifact.Windows.Sysinternals.Autoruns(Tool_Autorun_amd64_FILENAME='a.exe', Tool_Autorun_amd64_HASH='abc')",
    );
    expect(reasons.join(" ")).toContain("Tool_Autorun_amd64_FILENAME");
    expect(reasons.join(" ")).toContain("Windows.Sysinternals.Autoruns");
  });

  it("Windows.Hayabusa.Rules with no arguments is safe", () => {
    expect(vqlAllowed("SELECT * FROM Artifact.Windows.Hayabusa.Rules()")).toEqual({ ok: true });
  });

  it.each([
    "SELECT * FROM Artifact.Windows.Hayabusa.Rules(RuleLevel='Critical')",
    "SELECT * FROM Artifact.windows.sys.startupitems(x='1')",
    "SELECT * FROM Artifact.Windows.EventLogs.Chainsaw(SomeOption='Y')",
  ])("a Best Practice artifact with any argument is risky: %s", (vql) => {
    const reasons = expectRiskyOnly(vql);
    expect(reasons.some((r) => /only its default run/.test(r))).toBe(true);
  });

  it("EvtxHunter with its usual IdRegex arguments is still safe", () => {
    expect(
      vqlAllowed(
        "SELECT * FROM Artifact.Windows.EventLogs.EvtxHunter(EvtxGlob='C:/Windows/System32/winevt/Logs/*.evtx', IdRegex='^4624$')",
      ),
    ).toEqual({ ok: true });
  });

  it.each([
    "SELECT * FROM Artifact.Windows.EventLogs.EvtxHunter(Tool_X_URL='x')",
    "SELECT * FROM Artifact.Generic.Client.Info(tool_thing='x')",
    "SELECT * FROM Artifact.Windows.Search.FileFinder(SearchFilesGlob='C:/x', TOOL_Yara_URL='m')",
  ])("a Tool_ override on a reviewed artifact is risky: %s", (vql) => {
    const reasons = expectRiskyOnly(vql);
    expect(reasons.some((r) => /can change the tool, file or command/.test(r))).toBe(true);
  });

  it.each([
    "SELECT * FROM Artifact.Windows.EventLogs.EvtxHunter(PathRegex='Security', IdRegex='^4624$')",
    "SELECT * FROM Artifact.Windows.Search.FileFinder(SearchFilesGlob='C:/x/*', Calculate_Hash='Y', ExcludePathRegex='tmp')",
  ])("ordinary arguments on a reviewed artifact stay safe: %s", (vql) => {
    expect(vqlAllowed(vql)).toEqual({ ok: true });
  });

  it("keeps the upload refusal on a Best Practice artifact, beside the default-run reason", () => {
    const r = vqlAllowed("SELECT * FROM Artifact.Windows.Hayabusa.Rules(UploadResults='Y')");
    const reasons = r.ok ? [] : r.reasons;
    expect(reasons).toContain("argument UploadResults is refused (uploads, dumps and lambdas)");
  });

  it("a path argument on a plain file read is not affected", () => {
    expect(vqlAllowed("SELECT * FROM glob(globs='C:/x/*', root='C:/x')")).toEqual({ ok: true });
    expect(vqlAllowed("SELECT * FROM read_file(filenames='C:/x/a.txt')")).toEqual({ ok: true });
  });
});

describe("Watson's Velociraptor rules: Best Practice artifacts", () => {
  it("tells Watson to call a Best Practice artifact with no arguments", async () => {
    const { veloRulesText } = await import("../../../../src/analysis/ai/watson/velo/veloPrompt.js");
    const text = veloRulesText();
    expect(text).toContain("Call a Best Practice artifact");
    expect(text).toContain("with no arguments, as Artifact.<Name>(): its default run is the only safe form.");
    expect(text).toContain("makes the query risky, so the analyst must approve it.");
    expect(text).toContain("Tool_ is risky");
    expect(text).not.toContain("still apply to them");
  });
});
