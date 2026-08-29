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
import { NsrlStore } from "../../src/analysis/nsrlStore.js";
import { SlashCommandChannelStore } from "../../src/analysis/slashCommandStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { VeloMonitorStore } from "../../src/analysis/veloMonitorStore.js";
import { ClickUpExportStore } from "../../src/integrations/clickup/clickupExportStore.js";
import { JiraExportStore } from "../../src/integrations/jira/jiraExportStore.js";
import { NotionExportStore } from "../../src/integrations/notion/notionExportStore.js";
import { McpServerStore } from "../../src/integrations/mcp/mcpServerStore.js";
import { ServiceNowExportStore } from "../../src/integrations/servicenow/servicenowExportStore.js";
import { SocratesJobStore } from "../../src/integrations/socrates/socratesJobStore.js";
import { CustomToolStore } from "../../src/integrations/tools/customToolStore.js";
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

  // ── Integration + config stores (follow-up to #682) ────────────────────────────────────────────
  // Lower stakes than the decision stores — nothing here is evidence — but two of them reach outside
  // the tool, which is worth more than the tidiness of the file they live in.

  describe("export pointer stores", () => {
    // A missing ticket ref is how these stores say "no ticket exists yet", so losing one does not
    // just forget a pointer — the next export opens a DUPLICATE ticket in somebody else's queue.
    it("keeps every Jira issue ref when exports overlap", async () => {
      const store = new JiraExportStore(cases);
      await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) =>
          store.record(CASE, { [`f${i}`]: { id: `${i}`, key: `SOC-${i}` } }),
        ),
      );
      expect(Object.keys((await store.load(CASE)).issueRefs)).toHaveLength(CONCURRENT);
    });

    it("keeps every ServiceNow incident ref when exports overlap", async () => {
      const store = new ServiceNowExportStore(cases);
      await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) =>
          store.record(CASE, { [`f${i}`]: { id: `sys-${i}`, number: `INC${i}` } }),
        ),
      );
      expect(Object.keys((await store.load(CASE)).incidentRefs)).toHaveLength(CONCURRENT);
    });

    it("keeps every ClickUp task id when exports overlap", async () => {
      const store = new ClickUpExportStore(cases);
      await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) => store.record(CASE, { taskIds: { [`f${i}`]: `t${i}` } })),
      );
      expect(Object.keys((await store.load(CASE)).taskIds)).toHaveLength(CONCURRENT);
    });

    it("does not lose a Notion field written beside another", async () => {
      const store = new NotionExportStore(cases);
      await Promise.all([
        store.record(CASE, { pageId: "page-1" }),
        store.record(CASE, { lastBlocksAppended: 42 }),
      ]);
      const stored = await store.load(CASE);
      expect(stored.pageId).toBe("page-1");
      expect(stored.lastBlocksAppended).toBe(42);
    });
  });

  describe("VeloHuntStore / VeloMonitorStore / SocratesJobStore", () => {
    const hunt = (i: number) => ({
      bundleId: `b${i}`,
      bundleName: `Bundle ${i}`,
      artifacts: ["Windows.KapeFiles.Targets"],
      huntId: `H.${i}`,
      launchedAt: "2026-08-29T00:00:00.000Z",
      waitMinutes: 10,
      collectAt: "2026-08-29T00:10:00.000Z",
      status: "running" as const,
    });

    // A lost hunt record leaves a hunt RUNNING on the fleet that the analyst can neither see nor
    // collect.
    it("keeps every hunt when several are launched at once", async () => {
      const store = new VeloHuntStore(cases);
      await Promise.all(Array.from({ length: 12 }, (_, i) => store.upsert(CASE, hunt(i))));
      expect(await store.list(CASE)).toHaveLength(12);
    });

    it("updates a hunt in place rather than duplicating it", async () => {
      const store = new VeloHuntStore(cases);
      await store.upsert(CASE, hunt(1));
      await Promise.all([
        store.upsert(CASE, { ...hunt(1), status: "imported" }),
        store.upsert(CASE, hunt(2)),
      ]);
      const jobs = await store.list(CASE);
      expect(jobs).toHaveLength(2);
      expect(jobs.find((j) => j.huntId === "H.1")?.status).toBe("imported");
    });

    it("keeps every monitor, and a concurrent removal only removes its own", async () => {
      const store = new VeloMonitorStore(cases);
      const monitor = (i: number) => ({
        id: `C.${i}__Windows.Events.ProcessCreation`,
        clientId: `C.${i}`,
        artifact: "Windows.Events.ProcessCreation",
        pollSeconds: 60,
        cursor: 0,
        status: "active" as const,
        createdAt: "2026-08-29T00:00:00.000Z",
      });
      await Promise.all(Array.from({ length: 10 }, (_, i) => store.upsert(CASE, monitor(i))));
      expect(await store.list(CASE)).toHaveLength(10);
      await Promise.all([store.remove(CASE, monitor(0).id), store.upsert(CASE, monitor(10))]);
      const left = await store.list(CASE);
      expect(left).toHaveLength(10);
      expect(left.some((m) => m.id === monitor(0).id)).toBe(false);
      expect(left.some((m) => m.id === monitor(10).id)).toBe(true);
    });

    it("keeps every SO-CRATES job when several are submitted at once", async () => {
      const store = new SocratesJobStore(cases);
      await Promise.all(
        Array.from({ length: 12 }, (_, i) =>
          store.upsert(CASE, {
            jobId: `j${i}`,
            md5: `${i}`.padStart(32, "0"),
            sourceName: `sample-${i}.exe`,
            status: "processing" as const,
            startedAt: "2026-08-29T00:00:00.000Z",
          }),
        ),
      );
      expect(await store.list(CASE)).toHaveLength(12);
    });
  });

  describe("global config stores", () => {
    it("keeps every MCP server when many are added at once", async () => {
      const store = new McpServerStore(join(root, "mcp", "servers.json"));
      await Promise.all(
        Array.from({ length: 12 }, (_, i) => store.add({ id: `server-${i}`, label: `Server ${i}` })),
      );
      expect(await store.load()).toHaveLength(12);
    });

    it("does not lose an MCP add while another server is removed", async () => {
      const store = new McpServerStore(join(root, "mcp", "servers.json"));
      await store.add({ id: "doomed", label: "Doomed" });
      await Promise.all([store.remove("doomed"), store.add({ id: "kept", label: "Kept" })]);
      expect((await store.load()).map((s) => s.id)).toEqual(["kept"]);
    });

    it("keeps every custom tool when many are added at once", async () => {
      const store = new CustomToolStore(join(root, "tools", "tools.json"));
      await Promise.all(
        Array.from({ length: 12 }, (_, i) => store.add({ name: `Tool ${i}`, binary: `/usr/bin/tool${i}` })),
      );
      expect(await store.load()).toHaveLength(12);
    });

    // A lost binding makes the war-room bot answer a chat about the wrong case, or about none.
    it("keeps every chat binding when many are bound at once", async () => {
      const store = new SlashCommandChannelStore(join(root, "notifications", "bindings.json"));
      await Promise.all(
        Array.from({ length: 12 }, (_, i) =>
          store.bind(`slack:C${i}`, `case-${i}`, "2026-08-29T00:00:00.000Z"),
        ),
      );
      expect(Object.keys(await store.loadAll())).toHaveLength(12);
    });

    it("does not lose a binding while another is unbound", async () => {
      const store = new SlashCommandChannelStore(join(root, "notifications", "bindings.json"));
      await store.bind("slack:GONE", "case-old", "2026-08-29T00:00:00.000Z");
      await Promise.all([
        store.unbind("slack:GONE"),
        store.bind("slack:KEPT", "case-new", "2026-08-29T00:00:00.000Z"),
      ]);
      expect(Object.keys(await store.loadAll())).toEqual(["slack:KEPT"]);
    });
  });

  describe("SynthMetaStore", () => {
    const diff = { added: [], removed: [], changed: [] } as never;

    // The two stamp methods each load-merge-save the whole document, so run together the second
    // save drops the first one's field. reportWriter.ts reads secondLook.leads straight out of this
    // file, so the lost stamp takes second-look leads out of the REPORT — not just the dashboard.
    it("keeps both stamps when they are written at the same moment", async () => {
      const store = new SynthMetaStore(cases);
      await store.record(CASE, diff, "2026-08-29T00:00:00.000Z");
      await Promise.all([
        store.recordSecondLook(CASE, {
          at: "2026-08-29T00:00:00.000Z",
          summary: "sweep",
          promoted: 3,
          requests: 5,
          matched: 4,
          leads: ["missed persistence"],
        }),
        store.recordSecondOpinionPerf(CASE, {
          modelA: "a",
          modelB: "b",
          agreementCount: 8,
          deltaCount: 2,
          agreementRate: 0.8,
          at: "2026-08-29T00:00:00.000Z",
        }),
      ]);
      const meta = await store.load(CASE);
      expect(meta.secondLook?.leads).toHaveLength(1);
      expect(meta.secondOpinionPerf?.agreementCount).toBe(8);
    });

    // Synthesis holds one instance (aiProviders.ts) and the on-demand routes another
    // (runtimeStores.ts) — the two paths that actually collide here.
    it("serializes two store instances over the same case", async () => {
      const routes = new SynthMetaStore(cases);
      const synthesis = new SynthMetaStore(cases);
      await routes.record(CASE, diff, "2026-08-29T00:00:00.000Z");
      await Promise.all([
        routes.recordSecondLook(CASE, {
          at: "2026-08-29T00:00:00.000Z",
          summary: "sweep",
          promoted: 1,
          requests: 2,
          matched: 1,
          leads: ["from routes"],
        }),
        synthesis.recordSecondOpinionPerf(CASE, {
          modelA: "a",
          modelB: "b",
          agreementCount: 91,
          deltaCount: 9,
          agreementRate: 0.91,
          at: "2026-08-29T00:00:00.000Z",
        }),
      ]);
      const meta = await routes.load(CASE);
      expect(meta.secondLook?.leads).toHaveLength(1);
      expect(meta.secondOpinionPerf?.agreementCount).toBe(91);
    });
  });

  describe("NsrlStore", () => {
    it("keeps every hash when several imports land at once", async () => {
      const store = new NsrlStore(join(root, "nsrl", "hashes.txt"));
      const batch = (n: number) =>
        Array.from({ length: 5 }, (_, i) => `${n}${i}`.padStart(32, "a").slice(0, 32));
      await Promise.all(Array.from({ length: 6 }, (_, n) => store.addMany(batch(n))));
      expect(await store.load()).toHaveLength(30);
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
