import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CollectionPlanStore } from "../../src/analysis/collectionPlanStore.js";
import { DwellWindowStore } from "../../src/analysis/dwellWindowStore.js";
import { IocWhitelistStore } from "../../src/analysis/iocWhitelistStore.js";
import { NotificationConfigStore } from "../../src/analysis/notificationStore.js";
import { PlaybookStore } from "../../src/analysis/playbookStore.js";
import { parseChannelInput } from "../../src/analysis/notifications.js";
import { ReportVersionStore } from "../../src/reports/reportVersionStore.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";

// The sequel to collabStoreConcurrency.test.ts (#216), for the side stores it missed (#682). Each
// one load-modify-writes a whole JSON document. atomicWrite stops a TORN file; it does not stop a
// LOST one. Two team-mode requests both read the same snapshot, both apply their own change, and
// the second rename silently discards the other analyst's work.
let cases: CaseStore;
let root: string;
const CASE = "c1";
const CONCURRENT = 20;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-sidestore-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
});

describe("side store concurrency (#682)", () => {
  describe("DwellWindowStore", () => {
    it("keeps every window when many are added at once", async () => {
      const store = new DwellWindowStore(cases);
      await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) =>
          store.add(CASE, {
            label: `w${i}`,
            start: "2026-06-01T00:00:00Z",
            end: "2026-06-02T00:00:00Z",
          }),
        ),
      );
      const stored = await store.list(CASE);
      expect(stored).toHaveLength(CONCURRENT);
      expect(new Set(stored.map((w) => w.label)).size).toBe(CONCURRENT);
    });

    it("does not lose a concurrent add while another window is updated or removed", async () => {
      const store = new DwellWindowStore(cases);
      const seed = await store.add(CASE, {
        label: "seed",
        start: "2026-06-01T00:00:00Z",
        end: "2026-06-02T00:00:00Z",
      });
      const doomed = await store.add(CASE, {
        label: "doomed",
        start: "2026-06-01T00:00:00Z",
        end: "2026-06-02T00:00:00Z",
      });
      await Promise.all([
        store.update(CASE, seed.id, { label: "renamed" }),
        store.remove(CASE, doomed.id),
        store.add(CASE, { label: "kept", start: "2026-06-01T00:00:00Z", end: "2026-06-02T00:00:00Z" }),
      ]);
      const labels = (await store.list(CASE)).map((w) => w.label).sort();
      expect(labels).toEqual(["kept", "renamed"]);
    });

    it("keeps two cases independent while both are written concurrently", async () => {
      await cases.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
      const store = new DwellWindowStore(cases);
      const window = (label: string) => ({
        label,
        start: "2026-06-01T00:00:00Z",
        end: "2026-06-02T00:00:00Z",
      });
      await Promise.all([
        ...Array.from({ length: 6 }, (_, i) => store.add(CASE, window(`c1-${i}`))),
        ...Array.from({ length: 6 }, (_, i) => store.add("c2", window(`c2-${i}`))),
      ]);
      expect(await store.list(CASE)).toHaveLength(6);
      expect(await store.list("c2")).toHaveLength(6);
    });
  });

  describe("PlaybookStore", () => {
    it("keeps every task when many are added at once, with unique short ids", async () => {
      const store = new PlaybookStore(cases);
      await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) => store.add(CASE, { title: `task ${i}` })),
      );
      const stored = await store.load(CASE);
      expect(stored).toHaveLength(CONCURRENT);
      expect(new Set(stored.map((t) => t.title)).size).toBe(CONCURRENT);
      // nextShortId() counts from the stored list, so a lost update also hands out a duplicate
      // handle — and the analyst's "close T4" then closes somebody else's task.
      expect(new Set(stored.map((t) => t.shortId)).size).toBe(CONCURRENT);
    });

    it("keeps a concurrent status edit and a concurrent add", async () => {
      const store = new PlaybookStore(cases);
      const seed = await store.add(CASE, { title: "seed" });
      await Promise.all([
        store.update(CASE, seed.id, { status: "done" }),
        store.add(CASE, { title: "added" }),
      ]);
      const stored = await store.load(CASE);
      expect(stored).toHaveLength(2);
      expect(stored.find((t) => t.id === seed.id)?.status).toBe("done");
      expect(stored.some((t) => t.title === "added")).toBe(true);
    });

    // The app builds a PlaybookStore in runtimeStores.ts for the routes AND another in
    // aiProviders.ts for synthesis, both over the same case directory. A per-instance lock would
    // leave those two free to clobber each other, so this store's lock is module-level.
    it("serializes two store instances over the same case", async () => {
      const routes = new PlaybookStore(cases);
      const synthesis = new PlaybookStore(cases);
      await Promise.all([
        ...Array.from({ length: 10 }, (_, i) => routes.add(CASE, { title: `routes ${i}` })),
        ...Array.from({ length: 10 }, (_, i) => synthesis.add(CASE, { title: `synthesis ${i}` })),
      ]);
      expect(await routes.load(CASE)).toHaveLength(20);
    });
  });

  describe("CollectionPlanStore", () => {
    it("keeps every override when many steps are marked at once", async () => {
      const store = new CollectionPlanStore(cases);
      await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) =>
          store.set(CASE, `step-${i}`, { state: "collected", reason: `r${i}` }),
        ),
      );
      expect(Object.keys(await store.load(CASE))).toHaveLength(CONCURRENT);
    });

    it("does not lose a concurrent set while another step is cleared", async () => {
      const store = new CollectionPlanStore(cases);
      await store.set(CASE, "step-a", { state: "collected", reason: "" });
      await Promise.all([
        store.clear(CASE, "step-a"),
        store.set(CASE, "step-b", { state: "na", reason: "not applicable" }),
      ]);
      expect(Object.keys(await store.load(CASE))).toEqual(["step-b"]);
    });
  });

  describe("IocWhitelistStore", () => {
    it("keeps every rule when many are added at once", async () => {
      const store = new IocWhitelistStore(join(root, "whitelist", "rules.json"));
      await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) =>
          store.add({ match: "exact", pattern: `evil-${i}.example` }),
        ),
      );
      const stored = await store.load();
      expect(stored).toHaveLength(CONCURRENT);
      expect(new Set(stored.map((r) => r.pattern)).size).toBe(CONCURRENT);
    });

    it("keeps a concurrent bulk import and a single add", async () => {
      const store = new IocWhitelistStore(join(root, "whitelist", "rules.json"));
      await Promise.all([
        store.addMany(Array.from({ length: 10 }, (_, i) => ({ match: "exact" as const, pattern: `b${i}` }))),
        store.add({ match: "exact", pattern: "single" }),
      ]);
      const patterns = (await store.load()).map((r) => r.pattern);
      expect(patterns).toHaveLength(11);
      expect(patterns).toContain("single");
    });

    it("still de-duplicates identical rules raced against each other", async () => {
      const store = new IocWhitelistStore(join(root, "whitelist", "rules.json"));
      const added = await Promise.all(
        Array.from({ length: 8 }, () => store.add({ match: "exact", pattern: "same.example" })),
      );
      expect(await store.load()).toHaveLength(1);
      expect(new Set(added.map((r) => r.id)).size).toBe(1);
    });
  });

  describe("NotificationConfigStore", () => {
    const draft = (name: string) =>
      parseChannelInput({ type: "slack", name, webhookUrl: `https://hooks/${name}` }).draft!;

    it("keeps every channel when many are added at once", async () => {
      const store = new NotificationConfigStore(join(root, "notifications", "config.json"));
      await Promise.all(Array.from({ length: CONCURRENT }, (_, i) => store.add(draft(`ch${i}`))));
      const stored = await store.load();
      expect(stored).toHaveLength(CONCURRENT);
      expect(new Set(stored.map((c) => c.name)).size).toBe(CONCURRENT);
    });

    // The worst shape on this file: a lost update resurrects a channel the analyst switched OFF,
    // and it keeps pushing case detail to an external destination.
    it("does not resurrect a disabled channel through a concurrent add", async () => {
      const store = new NotificationConfigStore(join(root, "notifications", "config.json"));
      const live = await store.add(draft("live"));
      await Promise.all([
        store.update(live.id, { ...draft("live"), enabled: false }),
        store.add(draft("other")),
      ]);
      const stored = await store.load();
      expect(stored).toHaveLength(2);
      expect(stored.find((c) => c.id === live.id)?.enabled).toBe(false);
    });

    it("does not lose a concurrent add while another channel is removed", async () => {
      const store = new NotificationConfigStore(join(root, "notifications", "config.json"));
      const doomed = await store.add(draft("doomed"));
      await Promise.all([store.remove(doomed.id), store.add(draft("kept"))]);
      expect((await store.load()).map((c) => c.name)).toEqual(["kept"]);
    });
  });

  describe("ReportVersionStore", () => {
    const emptyDiffState = () => ({ findings: [], iocs: [], forensicTimeline: [] });

    it("gives every concurrent snapshot its own index entry and version label", async () => {
      const versions = new ReportVersionStore(cases);
      const summaries = await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) =>
          versions.snapshot(CASE, {
            markdown: `# report ${i}`,
            meta: emptyReportMeta(),
            state: emptyDiffState(),
          }),
        ),
      );
      const listed = await versions.list(CASE);
      // A lost index write orphans the record file on disk: the version exists but diff and restore
      // can never reach it, which is a hole in the audit trail.
      expect(listed).toHaveLength(CONCURRENT);
      // A duplicate "vN" label is the same hole seen from the dashboard's version picker.
      expect(new Set(listed.map((v) => v.version)).size).toBe(CONCURRENT);
      expect(new Set(summaries.map((v) => v.id)).size).toBe(CONCURRENT);
      for (const summary of summaries) {
        expect(await versions.get(CASE, summary.id)).not.toBeNull();
      }
    });

    it("still de-duplicates byte-identical regenerations raced against each other", async () => {
      const versions = new ReportVersionStore(cases);
      await Promise.all(
        Array.from({ length: 8 }, () =>
          versions.snapshot(CASE, {
            markdown: "# same",
            meta: emptyReportMeta(),
            state: emptyDiffState(),
          }),
        ),
      );
      expect(await versions.list(CASE)).toHaveLength(1);
    });
  });
});
