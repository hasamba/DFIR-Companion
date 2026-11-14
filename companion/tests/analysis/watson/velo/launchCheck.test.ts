import { describe, it, expect } from "vitest";
import { checkLaunch } from "../../../../src/analysis/ai/watson/velo/launchCheck.js";
import { canonicalVqlFingerprint } from "../../../../src/analysis/ai/watson/velo/vqlAllowed.js";
import { vqlFingerprint } from "../../../../src/analysis/huntOutcomes.js";
import { MAX_VQL_BYTES } from "../../../../src/analysis/vqlInput.js";
import {
  matchClient,
  type VeloClientRecord,
} from "../../../../src/integrations/velociraptor/clientInventory.js";

const PSLIST = "SELECT * FROM pslist()";

const inventory: VeloClientRecord[] = [
  { clientId: "C.alpha1", hostname: "WKS-ALPHA", fqdn: "wks-alpha.corp.example.com" },
  { clientId: "C.web1", hostname: "web01", fqdn: "web01.east.example.com" },
  { clientId: "C.web2", hostname: "web01", fqdn: "web01.west.example.com" },
];

const ctx = (deployed: string[] = []) => ({ inventory, deployed: new Set(deployed), matchClient });

describe("checkLaunch", () => {
  it("passes a read-only fleet hunt and returns its fingerprint", () => {
    const r = checkLaunch({ vql: PSLIST, mode: "hunt" }, ctx());
    expect(r).toEqual({ ok: true, mode: "hunt", fingerprint: vqlFingerprint(PSLIST) });
  });

  it("blocks VQL off the allowlist and names the calls", () => {
    const r = checkLaunch({ vql: "SELECT * FROM execve(argv=['calc'])", mode: "hunt" }, ctx());
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/^blocked: /);
    expect(r.reason).toContain("execve");
    expect(r.reasons?.join(" ")).toContain("execve");
  });

  it("refuses empty VQL", () => {
    expect(checkLaunch({ vql: "   \n ", mode: "hunt" }, ctx()).ok).toBe(false);
  });

  it("refuses VQL over the size cap", () => {
    const vql = `SELECT * FROM pslist() WHERE Name = '${"a".repeat(MAX_VQL_BYTES)}'`;
    const r = checkLaunch({ vql, mode: "hunt" }, ctx());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("too long");
  });

  it("refuses a re-run of a hunt that already ran, whatever the whitespace", () => {
    const r = checkLaunch(
      { vql: "SELECT  *\n FROM   pslist()  ", mode: "hunt" },
      ctx([vqlFingerprint(PSLIST)]),
    );
    expect(r).toEqual({ ok: false, reason: "this hunt already ran on the case" });
  });

  it("refuses a re-run that only adds a comment or changes keyword case", () => {
    const deployed = [canonicalVqlFingerprint(PSLIST)];
    expect(checkLaunch({ vql: "select * from pslist() -- again", mode: "hunt" }, ctx(deployed)).ok).toBe(
      false,
    );
  });

  it("resolves a known host for a collection", () => {
    const r = checkLaunch({ vql: PSLIST, mode: "collection", hostname: "wks-alpha" }, ctx());
    expect(r).toEqual({
      ok: true,
      mode: "collection",
      clientHost: "WKS-ALPHA",
      fingerprint: vqlFingerprint(PSLIST),
    });
    const fq = checkLaunch({ vql: PSLIST, mode: "collection", hostname: "web01.east.example.com" }, ctx());
    expect(fq.ok && fq.clientHost).toBe("web01");
  });

  it.each(["wks-beta", "wks-alpah", "", "   "])("refuses an unknown or misspelled host %j", (hostname) => {
    const r = checkLaunch({ vql: PSLIST, mode: "collection", hostname }, ctx());
    expect(r).toEqual({ ok: false, reason: "host not in the case's Velociraptor fleet" });
  });

  it("refuses a collection with no host instead of widening to a fleet hunt", () => {
    const r = checkLaunch({ vql: PSLIST, mode: "collection" }, ctx());
    expect(r.ok).toBe(false);
  });

  it("refuses a short name that matches more than one client", () => {
    const r = checkLaunch({ vql: PSLIST, mode: "collection", hostname: "web01" }, ctx());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("more than one");
  });

  it("refuses a fleet hunt that names a host", () => {
    expect(checkLaunch({ vql: PSLIST, mode: "hunt", hostname: "wks-alpha" }, ctx()).ok).toBe(false);
  });

  it("refuses an unknown mode", () => {
    const input = { vql: PSLIST, mode: "fleet" } as unknown as Parameters<typeof checkLaunch>[0];
    expect(checkLaunch(input, ctx()).ok).toBe(false);
  });

  it("refuses non-string VQL", () => {
    const input = { vql: 42, mode: "hunt" } as unknown as Parameters<typeof checkLaunch>[0];
    expect(checkLaunch(input, ctx()).ok).toBe(false);
  });
});
