import { describe, expect, it } from "vitest";
import { checkLaunch, sentTextAllowed } from "../../../../src/analysis/ai/watson/velo/launchCheck.js";
import { launchFingerprints } from "../../../../src/analysis/ai/watson/velo/launchFingerprint.js";
import {
  matchClient,
  type VeloClientRecord,
} from "../../../../src/integrations/velociraptor/clientInventory.js";

// Task 9: checkLaunch stays strict by default; a caller that opts in (allowRisky) gets a RISKY-only
// launch back as ok with its raw risky reasons. HARD reasons refuse in every case.

const EXECVE = "SELECT * FROM execve(argv=['calc'])";
const inventory: VeloClientRecord[] = [
  { clientId: "C.alpha1", hostname: "WKS-ALPHA", fqdn: "wks-alpha.corp.example.com" },
];
const ctx = (deployed: string[] = [], allowRisky?: boolean) => ({
  inventory,
  deployed: new Set(deployed),
  matchClient,
  ...(allowRisky === undefined ? {} : { allowRisky }),
});

describe("checkLaunch risk opt-in (Task 9)", () => {
  it("is strict by default: a risky query is refused", () => {
    const r = checkLaunch({ vql: EXECVE, mode: "hunt" }, ctx());
    expect(r.ok).toBe(false);
  });

  it("with allowRisky a risky-only query passes and names its raw risky reasons", () => {
    const r = checkLaunch({ vql: EXECVE, mode: "collection", hostname: "wks-alpha" }, ctx([], true));
    expect(r).toMatchObject({ ok: true, mode: "collection", clientHost: "WKS-ALPHA" });
    if (!r.ok) return;
    expect(r.risky).toEqual(["the VQL calls execve, which is not on Watson's read-only list"]);
  });

  it("a safe query has no risky list", () => {
    const r = checkLaunch({ vql: "SELECT * FROM pslist()", mode: "hunt" }, ctx([], true));
    expect(r.ok && r.risky).toBeFalsy();
  });

  it.each([
    "SELECT * FROM execve(argv=['calc']) -- hidden",
    "SELECT * FROM execve(argv=['calc'])​",
    "SELECT * FROM execve(argv=['''x'''])",
    "SELECT * FROM execve(argv=['a\n\nb'])",
    "SELECT * FROM execve(argv=['calc']",
  ])("HARD reasons refuse even with allowRisky: %j", (vql) => {
    expect(checkLaunch({ vql, mode: "hunt" }, ctx([], true)).ok).toBe(false);
  });

  it("already-ran and host problems stay refused with allowRisky", () => {
    expect(checkLaunch({ vql: EXECVE, mode: "hunt" }, ctx(launchFingerprints(EXECVE), true)).ok).toBe(false);
    expect(checkLaunch({ vql: EXECVE, mode: "collection", hostname: "nope" }, ctx([], true)).ok).toBe(false);
    expect(checkLaunch({ vql: EXECVE, mode: "hunt", hostname: "wks-alpha" }, ctx([], true)).ok).toBe(false);
  });

  it("sentTextAllowed still checks every sent statement when the raw text is only risky", () => {
    // Statement two hides a comment-only problem after a blank line: the per-statement pass must run.
    const vql = "SELECT * FROM execve(argv=['calc'])\n\nSELECT * FROM shell(cmd='x')";
    const r = sentTextAllowed(vql);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reasons.join(" ")).toContain("execve");
    expect(r.reasons.join(" ")).toContain("shell");
  });
});
