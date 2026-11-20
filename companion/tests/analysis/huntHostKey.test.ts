import { describe, it, expect } from "vitest";
import { buildHostKeyIndex, resolveHostKey, stableHostKey } from "../../src/analysis/huntHostKey.js";
import type { VeloHuntJob } from "../../src/analysis/veloHuntStore.js";

const job = (clients: { clientId: string; hostname: string; fqdn?: string }[]): VeloHuntJob => ({
  bundleId: "b",
  bundleName: "b",
  artifacts: [],
  huntId: "H.1",
  launchedAt: "",
  waitMinutes: 1,
  collectAt: "",
  status: "imported",
  reachedClients: clients.map((c) => ({ fqdn: "", os: "windows", ...c })),
});

describe("stable hunt host key (#2670)", () => {
  it("is the server plus the client id", () => {
    expect(stableHostKey("srv-a", "C.123")).toBe("srv-a/C.123");
    expect(stableHostKey("", "C.123")).toBe("default/C.123");
  });

  it("resolves a row's host by short name, FQDN or bare", () => {
    const idx = buildHostKeyIndex(
      [job([{ clientId: "C.1", hostname: "WS-01", fqdn: "ws-01.corp.test" }])],
      "s",
    );
    expect(resolveHostKey(idx, "ws-01")?.key).toBe("s/C.1");
    expect(resolveHostKey(idx, "WS-01.corp.test")?.key).toBe("s/C.1");
  });

  it("keeps one key across a rename the case learned", () => {
    const idx = buildHostKeyIndex([job([{ clientId: "C.1", hostname: "NEW-NAME" }])], "s");
    const renames = [
      { formerName: "OLD-NAME", currentName: "NEW-NAME", until: "2026-01-01T00:00:00Z", basis: "x" },
    ];
    expect(resolveHostKey(idx, "old-name", renames as never)?.key).toBe("s/C.1");
  });

  it("a host no hunt reported is a NAME key, never an answering client", () => {
    const k = resolveHostKey(buildHostKeyIndex([], "s"), "ws-09");
    expect(k).toMatchObject({ basis: "name", key: "name/WS-09" });
  });

  it("a short name two clients share is not guessed", () => {
    const idx = buildHostKeyIndex(
      [job([{ clientId: "C.1", hostname: "WS-01" }]), job([{ clientId: "C.2", hostname: "WS-01" }])],
      "s",
    );
    expect(resolveHostKey(idx, "WS-01")?.basis).toBe("name");
  });
});
