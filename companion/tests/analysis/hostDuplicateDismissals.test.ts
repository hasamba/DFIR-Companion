import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { HostDuplicateDismissalStore, dismissalKey } from "../../src/analysis/hostDuplicateDismissals.js";

let cases: CaseStore;
let store: HostDuplicateDismissalStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hostdupdismiss-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new HostDuplicateDismissalStore(cases);
});

describe("HostDuplicateDismissalStore", () => {
  it("returns an empty list for a case with no file", async () => {
    expect(await store.load("c1")).toEqual([]);
  });

  it("round-trips a dismissal", async () => {
    const d = {
      canonical: "win11.windomain.local",
      other: "win11",
      dismissedAt: "2026-08-15T10:00:00Z",
      dismissedBy: "alice",
    };
    await store.append("c1", d);
    expect(await store.load("c1")).toEqual([d]);
  });

  it("appends without dropping earlier dismissals", async () => {
    await store.append("c1", { canonical: "a.corp", other: "a", dismissedAt: "t1", dismissedBy: "x" });
    await store.append("c1", { canonical: "b.corp", other: "b", dismissedAt: "t2", dismissedBy: "y" });
    expect(await store.load("c1")).toHaveLength(2);
  });

  it("normalizes host names so a dismissal survives a casing change", async () => {
    await store.append("c1", {
      canonical: "WIN11.Windomain.Local",
      other: "WIN11",
      dismissedAt: "t",
      dismissedBy: "x",
    });
    const [row] = await store.load("c1");
    expect(row.canonical).toBe("win11.windomain.local");
    expect(row.other).toBe("win11");
  });

  it("is idempotent — appending the same pair twice stores one row", async () => {
    const d = { canonical: "a.corp", other: "a", dismissedAt: "t1", dismissedBy: "x" };
    await store.append("c1", d);
    await store.append("c1", { ...d, dismissedAt: "t2", dismissedBy: "y" });
    expect(await store.load("c1")).toHaveLength(1);
  });

  it("returns an empty list rather than throwing on a corrupt file", async () => {
    const { writeFile } = await import("node:fs/promises");
    await writeFile(join(cases.stateDir("c1"), "host-duplicate-dismissals.json"), "{ not json");
    expect(await store.load("c1")).toEqual([]);
  });

  it("dismissalKey is order-sensitive and case-insensitive", () => {
    expect(dismissalKey("A.corp", "A")).toBe(dismissalKey("a.corp", "a"));
    expect(dismissalKey("a.corp", "a")).not.toBe(dismissalKey("a", "a.corp"));
  });
});
