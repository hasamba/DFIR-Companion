import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  DiscoveredEntitiesStore,
  mergeDiscovered,
  suppressValue,
  unsuppressValue,
  sanitizeDiscovered,
  emptyDiscovered,
} from "../../src/analysis/anonDiscovered.js";

describe("anonDiscovered pure helpers", () => {
  it("mergeDiscovered dedupes case-insensitively and skips suppressed", () => {
    const prev = {
      discovered: [{ value: "WIN11", category: "HOST" as const }],
      suppressed: ["config\\powershellinfo.log"],
    };
    const next = mergeDiscovered(prev, [
      { value: "win11", category: "HOST" }, // dup (ci) → skipped
      { value: "vagrant", category: "USER" }, // new
      { value: "config\\PowershellInfo.log", category: "USER" }, // suppressed → skipped
    ]);
    expect(next.discovered.map((e) => e.value)).toEqual(["WIN11", "vagrant"]);
    expect(next.suppressed).toEqual(["config\\powershellinfo.log"]);
  });

  it("suppressValue removes from discovered and records the veto (lowercased)", () => {
    const prev = {
      discovered: [
        { value: "config\\PowershellInfo.log", category: "USER" as const },
        { value: "WIN11", category: "HOST" as const },
      ],
      suppressed: [],
    };
    const next = suppressValue(prev, "config\\PowershellInfo.log");
    expect(next.discovered.map((e) => e.value)).toEqual(["WIN11"]);
    expect(next.suppressed).toEqual(["config\\powershellinfo.log"]);
  });

  it("unsuppressValue lifts the veto", () => {
    const next = unsuppressValue({ discovered: [], suppressed: ["win11", "x"] }, "WIN11");
    expect(next.suppressed).toEqual(["x"]);
  });

  it("sanitizeDiscovered drops suppressed entries from the discovered list and lowercases the veto", () => {
    const s = sanitizeDiscovered({
      discovered: [
        { value: "WIN11", category: "HOST" },
        { value: "bad", category: "USER" },
      ],
      suppressed: ["BAD"],
    });
    expect(s.discovered.map((e) => e.value)).toEqual(["WIN11"]);
    expect(s.suppressed).toEqual(["bad"]);
  });
});

describe("DiscoveredEntitiesStore", () => {
  let cases: CaseStore;
  let store: DiscoveredEntitiesStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-disc-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new DiscoveredEntitiesStore(cases);
  });

  it("returns empty for a fresh case", async () => {
    expect(await store.load("c1")).toEqual(emptyDiscovered());
  });

  it("adds, suppresses (removes + vetoes), and restores — round-tripping to disk", async () => {
    await store.addDiscovered("c1", [
      { value: "WIN11", category: "HOST" },
      { value: "config\\PowershellInfo.log", category: "USER" },
    ]);
    expect((await store.load("c1")).discovered).toHaveLength(2);

    await store.suppress("c1", "config\\PowershellInfo.log");
    const cur = await store.load("c1");
    expect(cur.discovered.map((e) => e.value)).toEqual(["WIN11"]);
    expect(cur.suppressed).toEqual(["config\\powershellinfo.log"]);

    // A suppressed value is not re-added by a later discovery.
    await store.addDiscovered("c1", [{ value: "config\\PowershellInfo.log", category: "USER" }]);
    expect((await store.load("c1")).discovered.map((e) => e.value)).toEqual(["WIN11"]);

    await store.unsuppress("c1", "config\\PowershellInfo.log");
    expect((await store.load("c1")).suppressed).toEqual([]);
  });
});

// The redaction list has TWO writers that are not the same object: the OCR pass writes through the
// store built in composition/aiProviders.ts, and the analyst's suppress/unsuppress clicks write
// through the one built in routes/anonymization.ts. Both load-modify-write the whole file, so a
// click landing on a snapshot taken before the OCR pass saved discards what OCR just found — and a
// value that should be masked goes out UNMASKED in an exported screenshot. This is the one store in
// this class a SOLO analyst can trip: it needs no second person, only a background pass. That also
// makes a per-instance lock useless here; the lock has to be shared by every instance.
describe("DiscoveredEntitiesStore concurrency (follow-up to #682)", () => {
  let cases: CaseStore;
  const CASE = "c1";
  const CONCURRENT = 20;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-disc-race-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  });

  it("keeps every discovery when many OCR batches land at once", async () => {
    const store = new DiscoveredEntitiesStore(cases);
    await Promise.all(
      Array.from({ length: CONCURRENT }, (_, i) =>
        store.addDiscovered(CASE, [{ value: `HOST-${i}`, category: "HOST" }]),
      ),
    );
    const stored = await store.load(CASE);
    expect(stored.discovered).toHaveLength(CONCURRENT);
    expect(new Set(stored.discovered.map((e) => e.value)).size).toBe(CONCURRENT);
  });

  it("keeps every suppression when the analyst vetoes many values at once", async () => {
    const store = new DiscoveredEntitiesStore(cases);
    await store.addDiscovered(
      CASE,
      Array.from({ length: CONCURRENT }, (_, i) => ({ value: `NOISE-${i}`, category: "HOST" as const })),
    );
    await Promise.all(Array.from({ length: CONCURRENT }, (_, i) => store.suppress(CASE, `NOISE-${i}`)));
    const stored = await store.load(CASE);
    expect(stored.suppressed).toHaveLength(CONCURRENT);
    expect(stored.discovered).toHaveLength(0);
  });

  // The bug exactly as it reaches a real investigation: the OCR pass and the analyst hold SEPARATE
  // store objects over the same case. Losing the OCR write is the dangerous direction — the entity
  // is never tokenized again, so the real value appears in an exported screenshot.
  it("does not drop an OCR discovery when an analyst suppression lands at the same moment", async () => {
    const ocrPass = new DiscoveredEntitiesStore(cases); // composition/aiProviders.ts
    const analyst = new DiscoveredEntitiesStore(cases); // routes/anonymization.ts
    await analyst.addDiscovered(CASE, [{ value: "FALSE-POSITIVE", category: "HOST" }]);

    await Promise.all([
      ocrPass.addDiscovered(CASE, [{ value: "REAL-PII", category: "USER" }]),
      analyst.suppress(CASE, "FALSE-POSITIVE"),
    ]);

    const stored = await analyst.load(CASE);
    expect(stored.discovered.map((e) => e.value)).toEqual(["REAL-PII"]);
    expect(stored.suppressed).toEqual(["false-positive"]);
  });

  it("serializes a burst across two instances over the same case", async () => {
    const ocrPass = new DiscoveredEntitiesStore(cases);
    const analyst = new DiscoveredEntitiesStore(cases);
    await Promise.all([
      ...Array.from({ length: 10 }, (_, i) =>
        ocrPass.addDiscovered(CASE, [{ value: `ocr-${i}`, category: "HOST" }]),
      ),
      ...Array.from({ length: 10 }, (_, i) =>
        analyst.addDiscovered(CASE, [{ value: `manual-${i}`, category: "HOST" }]),
      ),
    ]);
    expect((await analyst.load(CASE)).discovered).toHaveLength(20);
  });

  it("keeps a suppression and an un-suppression of different values from erasing each other", async () => {
    const store = new DiscoveredEntitiesStore(cases);
    await store.addDiscovered(CASE, [{ value: "KEEP-VETO", category: "HOST" }]);
    await store.suppress(CASE, "LIFT-ME");
    await Promise.all([store.suppress(CASE, "KEEP-VETO"), store.unsuppress(CASE, "LIFT-ME")]);
    const stored = await store.load(CASE);
    expect(stored.suppressed).toEqual(["keep-veto"]);
  });

  it("keeps two cases independent while both are written concurrently", async () => {
    await cases.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
    const store = new DiscoveredEntitiesStore(cases);
    await Promise.all([
      ...Array.from({ length: 6 }, (_, i) =>
        store.addDiscovered(CASE, [{ value: `c1-${i}`, category: "HOST" }]),
      ),
      ...Array.from({ length: 6 }, (_, i) =>
        store.addDiscovered("c2", [{ value: `c2-${i}`, category: "HOST" }]),
      ),
    ]);
    expect((await store.load(CASE)).discovered).toHaveLength(6);
    expect((await store.load("c2")).discovered).toHaveLength(6);
  });
});
