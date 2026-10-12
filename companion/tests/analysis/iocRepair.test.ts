import { describe, it, expect } from "vitest";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { IOC } from "../../src/analysis/stateTypes.js";
import { coerceIocValues, dedupeIocsById } from "../../src/analysis/iocRepair.js";

describe("coerceIocValues (#2178)", () => {
  const row = (id: string, value: unknown): IOC =>
    ({ id, type: "other", value, firstSeen: "2026-01-01T00:00:00Z" }) as unknown as IOC;

  it("turns every non-string value into a string and reports each row", () => {
    const input = [
      row("a", 12345),
      row("b", true),
      row("c", null),
      row("d", { a: 1 }),
      row("e", ["x"]),
      row("f", undefined),
    ];
    const snapshot = JSON.stringify(input);
    const { iocs, coerced } = coerceIocValues(input);
    expect(iocs.map((i) => i.value)).toEqual(["12345", "true", "", '{"a":1}', '["x"]', ""]);
    expect(iocs.map((i) => i.id)).toEqual(["a", "b", "c", "d", "e", "f"]);
    expect(coerced).toEqual([
      { id: "a", from: "number" },
      { id: "b", from: "boolean" },
      { id: "c", from: "null" },
      { id: "d", from: "object" },
      { id: "e", from: "array" },
      { id: "f", from: "undefined" },
    ]);
    expect(JSON.stringify(input)).toBe(snapshot);
    expect(input[0].value).toBe(12345);
  });

  it("returns the same array when every value is already a string", () => {
    const input = [row("a", "1.2.3.4"), row("b", "evil.example")];
    const { iocs, coerced } = coerceIocValues(input);
    expect(iocs).toBe(input);
    expect(coerced).toEqual([]);
  });

  it("keeps healthy rows as the same objects in a mixed list and drops nothing", () => {
    const healthy = row("a", "1.2.3.4");
    const { iocs } = coerceIocValues([healthy, row("b", 7)]);
    expect(iocs).toHaveLength(2);
    expect(iocs[0]).toBe(healthy);
    expect(iocs[1].value).toBe("7");
  });
});

describe("dedupeIocsById", () => {
  it("collapses rows sharing the same id, keeping the first occurrence", () => {
    const state = {
      ...emptyState("c1"),
      iocs: [
        { id: "i001", type: "process" as const, value: "OneDrive.exe", firstSeen: "" },
        { id: "i016", type: "domain" as const, value: "desktop-mnnuhhu.localdomain", firstSeen: "" },
        { id: "i200", type: "other" as const, value: "C:\\AkiraSim\\", firstSeen: "" },
        { id: "i016", type: "domain" as const, value: "desktop-mnnuhhu.localdomain", firstSeen: "" },
        { id: "i201", type: "process" as const, value: "cloudflare.exe", firstSeen: "" },
        { id: "i016", type: "domain" as const, value: "desktop-mnnuhhu.localdomain", firstSeen: "" },
      ],
    };
    const { state: repaired, removed } = dedupeIocsById(state);
    expect(removed).toBe(2);
    expect(repaired.iocs).toHaveLength(4);
    expect(repaired.iocs.filter((i) => i.id === "i016")).toHaveLength(1);
    // Order + other entries untouched.
    expect(repaired.iocs.map((i) => i.id)).toEqual(["i001", "i016", "i200", "i201"]);
  });

  it("is a no-op (returns the same state instance) when there are no duplicates", () => {
    const state = {
      ...emptyState("c1"),
      iocs: [
        { id: "i001", type: "ip" as const, value: "10.0.0.5", firstSeen: "" },
        { id: "i002", type: "domain" as const, value: "evil.example", firstSeen: "" },
      ],
    };
    const { state: repaired, removed } = dedupeIocsById(state);
    expect(removed).toBe(0);
    expect(repaired).toBe(state);
  });
});
