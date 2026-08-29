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
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { FindingWorkflowStore } from "../../src/analysis/findingWorkflow.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { IocAliasStore } from "../../src/analysis/iocAlias.js";
import { LateralPathDismissStore } from "../../src/analysis/lateralPathDismiss.js";
import { LearnedPatternStore } from "../../src/analysis/learnedPatternStore.js";
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

  // ── The decision stores (follow-up to #682) ────────────────────────────────────────────────────
  // These hold ANALYST DECISIONS, which is what makes losing one worse than losing a row. A missing
  // comment is noticed; a missing dismissal or triage assignment leaves the case file reading as
  // though nobody ever made the call. Four of them are built TWICE by the app (runtimeStores.ts for
  // the routes, aiProviders.ts for synthesis), so their locks are module-level — a per-instance lock
  // guards an object, and what needs guarding is a file.

  describe("FindingWorkflowStore", () => {
    it("keeps every triage decision when many findings are patched at once", async () => {
      const store = new FindingWorkflowStore(cases);
      await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) =>
          store.patch(CASE, `f${i}`, { assignee: `analyst-${i}`, status: "in_progress" }),
        ),
      );
      const stored = await store.load(CASE);
      expect(stored).toHaveLength(CONCURRENT);
      expect(new Set(stored.map((r) => r.assignee)).size).toBe(CONCURRENT);
    });

    // routes/findings.ts and routes/cockpit.ts both patch this file — a lead assigning an owner
    // while an analyst sets a status is the traffic that collides.
    it("keeps an assignment and a status change to two findings from erasing each other", async () => {
      const store = new FindingWorkflowStore(cases);
      await store.patch(CASE, "f1", { assignee: "alice" });
      await Promise.all([
        store.patch(CASE, "f1", { status: "in_review" }),
        store.patch(CASE, "f2", { assignee: "bob" }),
      ]);
      const stored = await store.load(CASE);
      expect(stored).toHaveLength(2);
      expect(stored.find((r) => r.findingId === "f1")?.assignee).toBe("alice");
      expect(stored.find((r) => r.findingId === "f1")?.status).toBe("in_review");
      expect(stored.find((r) => r.findingId === "f2")?.assignee).toBe("bob");
    });

    it("does not lose a concurrent patch while another record is cleared", async () => {
      const store = new FindingWorkflowStore(cases);
      await store.patch(CASE, "gone", { assignee: "alice" });
      await Promise.all([
        store.patch(CASE, "gone", { assignee: "", status: null }),
        store.patch(CASE, "kept", { assignee: "bob" }),
      ]);
      expect((await store.load(CASE)).map((r) => r.findingId)).toEqual(["kept"]);
    });
  });

  describe("AssetOverridesStore", () => {
    it("keeps every rename when many land at once", async () => {
      const store = new AssetOverridesStore(cases);
      await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) => store.rename(CASE, `asset-${i}`, `Renamed ${i}`)),
      );
      expect(Object.keys((await store.load(CASE)).renames)).toHaveLength(CONCURRENT);
    });

    // The whole override document is rewritten on every edit, so edits to unrelated corners of the
    // graph destroy each other wholesale — not just the field they touched.
    it("keeps a rename, a merge, a link edit and a removal made at the same moment", async () => {
      const store = new AssetOverridesStore(cases);
      await Promise.all([
        store.rename(CASE, "host-a", "DC01"),
        store.mergeAsset(CASE, "host-dup", "host-a"),
        store.addLink(CASE, "host-a", "ioc-1"),
        store.removeAsset(CASE, "host-noise"),
      ]);
      const ov = await store.load(CASE);
      expect(ov.renames["host-a"]).toBe("DC01");
      expect(ov.merges["host-dup"]).toBe("host-a");
      expect(ov.addedLinks).toContainEqual({ asset: "host-a", ioc: "ioc-1" });
      expect(ov.removed).toContain("host-noise");
    });

    it("keeps every manually added asset when many are created at once", async () => {
      const store = new AssetOverridesStore(cases);
      const made = await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) =>
          store.addAsset(CASE, { name: `Manual ${i}`, type: "host" }),
        ),
      );
      expect((await store.load(CASE)).added).toHaveLength(CONCURRENT);
      expect(new Set(made.map((m) => m.asset.id)).size).toBe(CONCURRENT);
    });

    // The cycle check reads the merge map, so it has to run INSIDE the lock or a concurrent merge
    // can slip a cycle past it.
    it("still refuses a self-merge and a cycle under concurrent traffic", async () => {
      const store = new AssetOverridesStore(cases);
      await expect(store.mergeAsset(CASE, "a", "a")).rejects.toThrow(/into itself/);
      await store.mergeAsset(CASE, "a", "b");
      await expect(store.mergeAsset(CASE, "b", "a")).rejects.toThrow(/cycle/);
      expect((await store.load(CASE)).merges).toEqual({ a: "b" });
    });

    it("serializes two store instances over the same case", async () => {
      const routes = new AssetOverridesStore(cases);
      const synthesis = new AssetOverridesStore(cases);
      await Promise.all([
        ...Array.from({ length: 10 }, (_, i) => routes.rename(CASE, `r${i}`, `R${i}`)),
        ...Array.from({ length: 10 }, (_, i) => synthesis.rename(CASE, `s${i}`, `S${i}`)),
      ]);
      expect(Object.keys((await routes.load(CASE)).renames)).toHaveLength(20);
    });
  });

  describe("IocAliasStore", () => {
    it("keeps every alias when many merges are confirmed at once", async () => {
      const store = new IocAliasStore(cases);
      await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) => store.add(CASE, `dupe-${i}.example`, `ioc-${i}`)),
      );
      expect(Object.keys((await store.load(CASE)).aliases)).toHaveLength(CONCURRENT);
    });

    // A lost alias is not just a lost row: the un-merged duplicate reappears as its own IOC on the
    // next synthesis, which is the exact outcome the alias map exists to prevent.
    it("does not lose a concurrent merge while another is un-merged", async () => {
      const store = new IocAliasStore(cases);
      await store.add(CASE, "old.example", "ioc-old");
      await Promise.all([store.remove(CASE, "old.example"), store.add(CASE, "new.example", "ioc-new")]);
      expect((await store.load(CASE)).aliases).toEqual({ "new.example": "ioc-new" });
    });
  });

  describe("LateralPathDismissStore", () => {
    it("keeps every dismissed chain when many are ruled out at once", async () => {
      const store = new LateralPathDismissStore(cases);
      await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) =>
          store.add(CASE, [`host-${i}`, `host-${i}-b`], `benign ${i}`),
        ),
      );
      expect(await store.load(CASE)).toHaveLength(CONCURRENT);
    });

    it("does not lose a concurrent dismissal while another chain is restored", async () => {
      const store = new LateralPathDismissStore(cases);
      const gone = await store.add(CASE, ["a", "b"], "restore me");
      await Promise.all([store.remove(CASE, gone!.key), store.add(CASE, ["c", "d"], "keep me")]);
      const stored = await store.load(CASE);
      expect(stored).toHaveLength(1);
      expect(stored[0].note).toBe("keep me");
    });
  });

  describe("HostDuplicateDismissalStore", () => {
    // Losing one of these re-arms the merge gate, and the gate BLOCKS synthesis — so the lost write
    // does not just forget a decision, it stalls the case.
    it("keeps every dismissed pair when many are judged at once", async () => {
      const store = new HostDuplicateDismissalStore(cases);
      await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) =>
          store.append(CASE, {
            canonical: `host-${i}.corp.example`,
            other: `host-${i}`,
            dismissedAt: "2026-08-29T00:00:00.000Z",
            dismissedBy: `analyst-${i}`,
          }),
        ),
      );
      expect(await store.load(CASE)).toHaveLength(CONCURRENT);
    });

    it("stays idempotent when the same pair is dismissed twice at once", async () => {
      const store = new HostDuplicateDismissalStore(cases);
      const pair = {
        canonical: "dc01.corp.example",
        other: "dc01",
        dismissedAt: "2026-08-29T00:00:00.000Z",
        dismissedBy: "alice",
      };
      await Promise.all([store.append(CASE, pair), store.append(CASE, { ...pair, dismissedBy: "bob" })]);
      const stored = await store.load(CASE);
      expect(stored).toHaveLength(1);
      // First decision wins — the recorded analyst must stay whoever actually made the call.
      expect(stored[0].dismissedBy).toBe("alice");
    });

    it("serializes two store instances over the same case", async () => {
      const routes = new HostDuplicateDismissalStore(cases);
      const gate = new HostDuplicateDismissalStore(cases);
      await Promise.all([
        ...Array.from({ length: 10 }, (_, i) =>
          routes.append(CASE, {
            canonical: `r${i}.corp.example`,
            other: `r${i}`,
            dismissedAt: "2026-08-29T00:00:00.000Z",
            dismissedBy: "a",
          }),
        ),
        ...Array.from({ length: 10 }, (_, i) =>
          gate.append(CASE, {
            canonical: `g${i}.corp.example`,
            other: `g${i}`,
            dismissedAt: "2026-08-29T00:00:00.000Z",
            dismissedBy: "b",
          }),
        ),
      ]);
      expect(await routes.load(CASE)).toHaveLength(20);
    });
  });

  describe("LearnedPatternStore", () => {
    // routes/findings.ts records a BULK dismissal one finding at a time, so a single analyst action
    // is already a burst against this file.
    it("keeps every reasoned dismissal when a bulk dismissal is recorded at once", async () => {
      const store = new LearnedPatternStore(cases);
      await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) =>
          store.record(CASE, { text: `benign scheduled task ${i}`, reason: "known-good-tool" }),
        ),
      );
      expect(await store.load(CASE)).toHaveLength(CONCURRENT);
    });

    // A bulk dismissal is ONE analyst click. Folding it into a single load->merge->save keeps the
    // work flat instead of re-reading and rewriting the whole ledger once per dismissed finding.
    it("records a whole batch in one write", async () => {
      const store = new LearnedPatternStore(cases);
      const inputs = Array.from({ length: CONCURRENT }, (_, i) => ({
        text: `benign maintenance script ${i}`,
        reason: "known-good-tool" as const,
      }));
      expect(await store.recordMany(CASE, inputs)).toHaveLength(CONCURRENT);
      expect(await store.load(CASE)).toHaveLength(CONCURRENT);
    });

    it("leaves the ledger untouched for an empty batch", async () => {
      const store = new LearnedPatternStore(cases);
      await store.record(CASE, { text: "already here", reason: "duplicate" });
      expect(await store.recordMany(CASE, [])).toHaveLength(1);
    });

    it("keeps concurrent batches from overwriting each other", async () => {
      const store = new LearnedPatternStore(cases);
      await Promise.all([
        store.recordMany(CASE, [
          { text: "first batch alpha", reason: "known-good-tool" },
          { text: "first batch bravo", reason: "known-good-tool" },
        ]),
        store.recordMany(CASE, [
          { text: "second batch charlie", reason: "authorized-test" },
          { text: "second batch delta", reason: "authorized-test" },
        ]),
      ]);
      expect(await store.load(CASE)).toHaveLength(4);
    });

    it("serializes two store instances over the same case", async () => {
      const routes = new LearnedPatternStore(cases);
      const synthesis = new LearnedPatternStore(cases);
      await Promise.all([
        ...Array.from({ length: 8 }, (_, i) =>
          routes.record(CASE, { text: `routes pattern ${i}`, reason: "detection-misfire" }),
        ),
        ...Array.from({ length: 8 }, (_, i) =>
          synthesis.record(CASE, { text: `synthesis pattern ${i}`, reason: "authorized-test" }),
        ),
      ]);
      expect(await routes.load(CASE)).toHaveLength(16);
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
