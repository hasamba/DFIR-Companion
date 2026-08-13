import { describe, it, expect } from "vitest";
import {
  canonicalHostName,
  buildHostAliasIndex,
  resolveHost,
  findNearDuplicates,
} from "../../src/analysis/hostAlias.js";

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
