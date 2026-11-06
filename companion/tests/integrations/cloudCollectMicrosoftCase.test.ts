import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createCollection, runCollection } from "../../src/integrations/cloudCollect/collectEngine.js";
import { collectionPaths, parseManifest } from "../../src/integrations/cloudCollect/collectManifest.js";
import { QueryUsageStore } from "../../src/integrations/cloudCollect/collectBudget.js";
import { readCheckpoint } from "../../src/integrations/cloudCollect/collectCheckpoint.js";
import { nodeCollectFs } from "../../src/integrations/cloudCollect/collectFs.js";
import type { CollectionCheckpoint } from "../../src/integrations/cloudCollect/collectTypes.js";
import type { OpenCloudAccount } from "../../src/integrations/cloudAccounts/types.js";
import { microsoftCollectProvider } from "../../src/integrations/cloudCollectMicrosoft/microsoftProvider.js";
import { faultFs, pipelineImporter, tempCase, type TempCase } from "../helpers/cloudCollectFakes.js";
import { fakeClock } from "../helpers/cloudCollectDense.js";
import { pollBudget, pollFor } from "../helpers/poll.js";
import {
  activityRecord,
  directoryAuditRecord,
  graphUalRecord,
  legacyUalRecord,
  mockTenant,
  signInRecord,
  type MockTenantOptions,
} from "../helpers/microsoftCollectMocks.js";

// #2315 end to end: the Microsoft collector, the #2311/#2312 engine, and the real import pipeline in
// a temp case — mocked Graph and ARM only. The Graph audit records must grade exactly like the
// legacy UAL records they wrap (#2304 parity).

const TENANT = "00000000-0000-4000-8000-000000000001";
const SUB = "11111111-1111-4111-8111-111111111111";
const WINDOW = { start: "2026-10-01T10:00:00.000Z", end: "2026-10-01T11:00:00.000Z" };
const at = (min: number) => new Date(Date.parse(WINDOW.start) + min * 60_000 + 7_000).toISOString();
let tick = 0;
const now = () => new Date(Date.UTC(2026, 9, 5, 0, 0, tick++)).toISOString();

const account = {
  id: "acct1",
  name: "lab tenant",
  revision: 1,
  createdAt: "",
  updatedAt: "",
  provider: "microsoft",
  settings: { tenantId: TENANT, clientId: "00000000-0000-4000-8000-000000000002", certificateFormat: "pem" },
  secrets: { certificatePem: "unused-by-the-mock" },
} as OpenCloudAccount;

interface RunOpts {
  sources: string[];
  budget?: number;
  onPoll?: () => Promise<void>;
}

async function collect(t: TempCase, tenantOpts: MockTenantOptions, opts: RunOpts) {
  const tenant = mockTenant(tenantOpts);
  const clock = fakeClock(Date.parse("2026-10-05T00:00:00Z"));
  const provider = microsoftCollectProvider({
    wire: () => ({ graph: tenant.call, arm: tenant.call }),
    timing: {
      now: clock.now,
      sleep: async (ms) => {
        await opts.onPoll?.();
        await clock.sleep(ms);
      },
    },
  });
  const session = provider.open(account);
  const fs = faultFs();
  await createCollection(
    fs,
    session,
    {
      dir: t.dir,
      collectionId: "cc-test-abc123",
      caseId: "c1",
      accountId: "acct1",
      accountName: "lab tenant",
      provider: "microsoft",
      sources: opts.sources,
      window: WINDOW,
      filters: {},
      companionVersion: "0.0.0-test",
    },
    now,
  );
  const usage = join(await mkdtemp(join(tmpdir(), "dfir-m365-quota-")), "query-usage.json");
  const scope = provider.quotaScope?.(account.settings as unknown as Record<string, unknown>) ?? "";
  const budget = opts.budget ? new QueryUsageStore(usage).budget(scope, opts.budget) : undefined;
  const cp = await runCollection(
    {
      fs,
      session,
      importer: pipelineImporter(t),
      sources: provider.sources,
      now,
      clock,
      ...(budget ? { budget } : {}),
    },
    t.dir,
    { resume: false },
  );
  return { cp, tenant };
}

async function manifest(t: TempCase) {
  return parseManifest(await readFile(collectionPaths(t.dir).manifest, "utf8"));
}

/** Title + severity of each forensic timeline event, sorted: what "grades the same" compares. */
async function graded(t: TempCase): Promise<string[]> {
  const state = await t.stateStore.load("c1");
  return state.forensicTimeline.map((e) => `${e.severity} | ${e.description}`).sort();
}

describe("Microsoft collection into a case (#2315)", () => {
  it("saves every page with its hash, imports it, and grades Graph records exactly like legacy UAL", async () => {
    const ops = ["New-InboxRule", "Set-Mailbox", "Add-MailboxPermission"];
    const graph = ops.map((op, i) => graphUalRecord(i, at(i * 10), op));
    const t = await tempCase();
    const { cp } = await collect(t, { ual: graph, pollStatuses: ["running"] }, { sources: ["m365-ual"] });
    expect(cp.status).toBe("complete");
    const m = await manifest(t);
    expect(m.pages.length).toBeGreaterThan(0);
    for (const p of m.pages) {
      const body = await readFile(join(collectionPaths(t.dir).pages, p.file));
      expect(createHash("sha256").update(body).digest("hex")).toBe(p.sha256);
      expect(JSON.parse(body.toString("utf8"))).toHaveProperty("value"); // Graph's wrapper, as sent
    }
    expect(cp.imported).toHaveLength(m.pages.length);

    // The legacy UAL export of the same three records, imported the existing way into another case.
    const legacy = await tempCase();
    const file = join(legacy.root, "UAL-legacy.json");
    await writeFile(file, JSON.stringify(ops.map((op, i) => legacyUalRecord(i, at(i * 10), op))));
    await legacy.pipeline.importCloudFile("c1", "m365", file, {
      label: "UAL-legacy.json",
      idPrefix: "legacy",
      importedAt: "2026-10-05T00:00:00.000Z",
    });

    const collected = await graded(t);
    expect(collected.length).toBeGreaterThan(0);
    expect(collected).toEqual(await graded(legacy));
    expect(collected.some((g) => /^(High|Critical|Medium)/.test(g))).toBe(true);
  });

  it("splits a truncated query window in halves, and every record still lands", async () => {
    const ual = Array.from({ length: 6 }, (_, i) => graphUalRecord(i, at(i * 10)));
    const t = await tempCase();
    const { cp, tenant } = await collect(t, { ual, recordCap: 3 }, { sources: ["m365-ual"] });
    expect(cp.status).toBe("complete");
    const m = await manifest(t);
    expect(m.entries.some((e) => e.type === "split" && e.mode === "time")).toBe(true);
    expect(tenant.created.length).toBeGreaterThan(1);
    const windows = tenant.created.map((q) => `${q.filterStartDateTime}→${q.filterEndDateTime}`);
    expect(windows[0]).toBe(`${WINDOW.start}→${WINDOW.end}`);
    const leaves = cp.subWindows.filter((s) => s.state === "done" && s.source === "m365-ual");
    expect(leaves.reduce((n, s) => n + s.records, 0)).toBeGreaterThanOrEqual(6);
  });

  it("stops 'partial — budget used' when the tenant's query budget runs out", async () => {
    const ual = Array.from({ length: 6 }, (_, i) => graphUalRecord(i, at(i * 10)));
    const t = await tempCase();
    const { cp, tenant } = await collect(t, { ual, recordCap: 3 }, { sources: ["m365-ual"], budget: 2 });
    expect(tenant.created).toHaveLength(2);
    expect(cp.status).toBe("partial");
    expect(cp.stopReason).toMatch(/partial — budget used/);
    expect(cp.missing.length).toBeGreaterThan(0);
  });

  it("shows the audit query's status in the checkpoint while it waits", async () => {
    const t = await tempCase();
    const seen: string[] = [];
    await collect(
      t,
      { ual: [graphUalRecord(1, at(1))], pollStatuses: ["notStarted", "running"] },
      {
        sources: ["m365-ual"],
        onPoll: async () => {
          if (seen.length) return;
          // Wait (bounded) for the status write to land: a checkpoint commit fsyncs, slow on Windows.
          const status = await pollFor(
            "a provider status in the checkpoint",
            async () => {
              const cp = await readCheckpoint(nodeCollectFs, collectionPaths(t.dir));
              return cp?.subWindows.find((sw) => sw.providerStatus)?.providerStatus ?? null;
            },
            { timeoutMs: pollBudget(5_000) },
          );
          seen.push(status);
        },
      },
    );
    expect(seen.some((s) => /audit query (notStarted|running)/.test(s))).toBe(true);
    const final = JSON.parse(
      await readFile(collectionPaths(t.dir).checkpoint, "utf8"),
    ) as CollectionCheckpoint;
    expect(final.subWindows.every((s) => !s.providerStatus)).toBe(true); // cleared by the page
  });

  it("imports Entra directory audits, every sign-in category and Azure Activity pages", async () => {
    const types = ["interactiveUser", "nonInteractiveUser", "servicePrincipal", "managedIdentity"];
    const t = await tempCase();
    const sources = [
      "entra-directory-audits",
      "entra-signins-interactive",
      "entra-signins-noninteractive",
      "entra-signins-serviceprincipal",
      "entra-signins-managedidentity",
      "azure-activity",
    ];
    const { cp } = await collect(
      t,
      {
        directoryAudits: [directoryAuditRecord(1, at(5))],
        signIns: types.map((ty, i) => signInRecord(i, at(10 + i), ty)),
        subscriptions: [SUB],
        activity: { [SUB]: [activityRecord(1, at(20), SUB)] },
      },
      { sources },
    );
    expect(cp.status).toBe("complete");
    const perSource = new Map(sources.map((s) => [s, 0]));
    for (const sw of cp.subWindows) perSource.set(sw.source, (perSource.get(sw.source) ?? 0) + sw.records);
    expect([...perSource.values()]).toEqual([1, 1, 1, 1, 1, 1]); // which categories were collected
    const m = await manifest(t);
    expect(cp.imported).toHaveLength(m.pages.length);
    // Every page landed as an event: sign-ins in the super-timeline (Info), the role grants promoted.
    const rows = (await t.superTimelineStore.query("c1", {})).events;
    const state = await t.stateStore.load("c1");
    const landed = new Set([...rows, ...state.forensicTimeline].flatMap((e) => e.sourceScreenshots));
    for (const p of m.pages) expect(landed, p.file).toContain(`evidence/cloud/cc-test-abc123/${p.file}`);
    expect(rows.some((e) => /Entra sign-in: application svc-test/.test(e.description))).toBe(true);
    expect(state.forensicTimeline.some((e) => /role/i.test(e.description))).toBe(true);
  });
});
