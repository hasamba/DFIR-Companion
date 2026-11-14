import { describe, it, expect, vi } from "vitest";

// G1: the launch check must run the allowlist on the statements the launch path will SEND, not
// only on the VQL as written. Simulate a splitter whose output differs from its input.
vi.mock("../../../../src/analysis/vqlStatements.js", async (orig) => {
  const real = await orig<typeof import("../../../../src/analysis/vqlStatements.js")>();
  return {
    ...real,
    splitVqlStatements: (vql: string) =>
      vql.includes("pslist") ? ["SELECT * FROM execve(argv=['calc'])"] : real.splitVqlStatements(vql),
  };
});

const { checkLaunch } = await import("../../../../src/analysis/ai/watson/velo/launchCheck.js");
const { matchClient } = await import("../../../../src/integrations/velociraptor/clientInventory.js");

describe("checkLaunch checks the split output", () => {
  it("refuses when a statement that will be sent fails the allowlist", () => {
    const ctx = { inventory: [], deployed: new Set<string>(), matchClient };
    const r = checkLaunch({ vql: "SELECT * FROM pslist()", mode: "hunt" }, ctx);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("execve");
    expect(checkLaunch({ vql: "SELECT * FROM info()", mode: "hunt" }, ctx).ok).toBe(true);
  });
});
