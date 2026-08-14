import { describe, it, expect } from "vitest";
import {
  canonicalHostName,
  buildHostAliasIndex,
  hostMergesFromAssetIds,
  resolveHost,
  findNearDuplicates,
} from "../../src/analysis/hostAlias.js";

// AssetOverridesStore.mergeAsset persists asset ids ("host:ws-042.corp.local"), not host names.
// Fed straight to buildHostAliasIndex those keys match nothing, so every analyst merge was a
// silent no-op and merged machines stayed split across two rows in the ledger and the report.
describe("hostMergesFromAssetIds", () => {
  it("unwraps host asset ids into host names", () => {
    expect(hostMergesFromAssetIds({ "host:ws-042.corp.local": "host:ws-042.example.invalid" })).toEqual({
      "ws-042.corp.local": "ws-042.example.invalid",
    });
  });

  it("ignores merges that are not host-to-host", () => {
    expect(
      hostMergesFromAssetIds({
        "account:svc-backup": "account:svc-backup@corp",
        "host:ws-042": "account:ws-042",
        "service:sshd": "service:ssh",
      }),
    ).toEqual({});
  });

  it("applies a persisted merge end to end", () => {
    const index = buildHostAliasIndex(
      [{ clientId: "C.1", hostname: "ws-042", fqdn: "ws-042.corp.local" }],
      hostMergesFromAssetIds({ "host:ws-042.corp.local": "host:ws-042.example.invalid" }),
    );
    expect(resolveHost(index, "ws-042.corp.local")).toBe("ws-042.example.invalid");
    expect(resolveHost(index, "ws-042")).toBe("ws-042.example.invalid");
    expect(resolveHost(index, "C.1")).toBe("ws-042.example.invalid");
  });
});

describe("canonicalHostName", () => {
  it("lowercases and trims", () => {
    expect(canonicalHostName("  WS-042  ")).toBe("ws-042");
  });

  it("strips a trailing dot from an FQDN but keeps the domain", () => {
    expect(canonicalHostName("WS-042.CORP.LOCAL.")).toBe("ws-042.corp.local");
  });

  it("returns an empty string for junk input", () => {
    expect(canonicalHostName("   ")).toBe("");
  });
});

describe("buildHostAliasIndex + resolveHost", () => {
  const index = buildHostAliasIndex(
    [{ clientId: "C.1234", hostname: "WS-042", fqdn: "ws-042.corp.local" }],
    {},
  );

  it("resolves the short name to the FQDN", () => {
    expect(resolveHost(index, "WS-042")).toBe("ws-042.corp.local");
  });

  it("resolves the client id to the FQDN", () => {
    expect(resolveHost(index, "C.1234")).toBe("ws-042.corp.local");
  });

  it("passes an unknown host through, canonicalized", () => {
    expect(resolveHost(index, "SRV-DC1")).toBe("srv-dc1");
  });

  it("honours an analyst merge over the fleet mapping", () => {
    const merged = buildHostAliasIndex(
      [{ clientId: "C.1234", hostname: "WS-042", fqdn: "ws-042.corp.local" }],
      { "ws-042.corp.local": "ws-042.example.invalid" },
    );
    expect(resolveHost(merged, "WS-042")).toBe("ws-042.example.invalid");
  });

  // Merges chain, and the overrides record carries them in whatever order the analyst made them.
  // assetOverrides.resolveCanonical walks the chain to its end, so the ledger must too or the same
  // merge data resolves one way in the asset graph and another here.
  it("follows a merge chain recorded out of order", () => {
    const merged = buildHostAliasIndex([{ clientId: "C.1", hostname: "a", fqdn: "a.example.invalid" }], {
      "b.example.invalid": "c.example.invalid",
      "a.example.invalid": "b.example.invalid",
    });
    expect(resolveHost(merged, "a.example.invalid")).toBe("c.example.invalid");
    expect(resolveHost(merged, "C.1")).toBe("c.example.invalid");
  });

  it("ignores a merge cycle rather than looping", () => {
    const merged = buildHostAliasIndex([], {
      "a.example.invalid": "b.example.invalid",
      "b.example.invalid": "a.example.invalid",
    });
    expect(resolveHost(merged, "a.example.invalid")).toBeTruthy();
  });

  it("leaves a host merged onto itself alone", () => {
    const merged = buildHostAliasIndex(
      [{ clientId: "C.1", hostname: "ws-9", fqdn: "ws-9.example.invalid" }],
      { "ws-9.example.invalid": "ws-9.example.invalid" },
    );
    expect(resolveHost(merged, "C.1")).toBe("ws-9.example.invalid");
    expect(resolveHost(merged, "ws-9")).toBe("ws-9.example.invalid");
  });
});

describe("findNearDuplicates", () => {
  it("reports a short name and an FQDN that were never linked by the fleet", () => {
    const index = buildHostAliasIndex([], {});
    const dupes = findNearDuplicates(index, ["ws-099", "ws-099.corp.local"]);
    expect(dupes).toEqual([{ canonical: "ws-099.corp.local", other: "ws-099", reason: "shortname-fqdn" }]);
  });

  it("reports nothing once the fleet has linked them", () => {
    const index = buildHostAliasIndex(
      [{ clientId: "C.9", hostname: "ws-099", fqdn: "ws-099.corp.local" }],
      {},
    );
    expect(findNearDuplicates(index, ["ws-099", "ws-099.corp.local"])).toEqual([]);
  });
});
