import { describe, expect, it } from "vitest";
import { REFUSED_VQL_KEEP, storedRequest } from "../../../src/analysis/ai/watson/roundOutcome.js";
import { MAX_VQL_BYTES } from "../../../src/analysis/vqlInput.js";

// Final review G16: the stored copy of a refused oversize VQL is clipped, never kept whole.

const req = (vql: string) => ({
  kind: "velociraptor" as const,
  mode: "hunt" as const,
  title: "t",
  vql,
  why: "w",
});

describe("storedRequest", () => {
  it("clips an oversize VQL to 2000 characters and says how much was cut", () => {
    const vql = "x".repeat(MAX_VQL_BYTES + 10);
    const out = storedRequest(req(vql));
    expect(out.kind === "velociraptor" && out.vql).toBe(
      `${"x".repeat(REFUSED_VQL_KEEP)}…(${vql.length - REFUSED_VQL_KEEP} more characters, refused as too long)`,
    );
  });

  it("keeps a VQL within the limit, and other requests, as they are", () => {
    const ok = req("SELECT * FROM pslist()");
    expect(storedRequest(ok)).toBe(ok);
    const q = { kind: "query" as const, language: "kql", query: "x".repeat(MAX_VQL_BYTES + 10), why: "w" };
    expect(storedRequest(q)).toBe(q);
  });
});
