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
