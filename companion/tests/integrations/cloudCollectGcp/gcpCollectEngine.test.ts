import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { createCollection, runCollection } from "../../../src/integrations/cloudCollect/collectEngine.js";
import { collectionPaths, parseManifest } from "../../../src/integrations/cloudCollect/collectManifest.js";
import type {
  CloudCollectSession,
  CollectSourceInfo,
  CollectWindow,
  ManifestPage,
} from "../../../src/integrations/cloudCollect/collectTypes.js";
import {
  GCP_AUDIT_SOURCE,
  GCP_COLLECT_SOURCES,
  GCP_SINK_SOURCE,
  gcpCollectSession,
} from "../../../src/integrations/cloudCollectGcp/gcpCollectProvider.js";
import { GCP_ENTRIES_LIST_URL } from "../../../src/integrations/cloudCollectGcp/gcpFilter.js";
import {
  SINK_UNVERIFIED_NOTE,
  lastCompleteBatchEnd,
} from "../../../src/integrations/cloudCollectGcp/gcpSink.js";
import { faultFs, pipelineImporter, tempCase, type TempCase } from "../../helpers/cloudCollectFakes.js";
import { fakeClock } from "../../helpers/cloudCollectDense.js";
import { gcpAuditEntry, googleError, mockWire, PROJECT } from "./gcpCollectMocks.js";

// #2314 end to end: the GCP session driven by the real engine into a temp case — evidence pages,
// manifest, restart on an expired token, the logName partition, throttling, the sink's cutoff, and
// events graded by the existing GCP rules.

const SETTINGS = {
  projectId: PROJECT,
  authMode: "service-account-key" as const,
  clientEmail: "c@example.com",
};
const WINDOW: CollectWindow = { start: "2026-11-01T00:00:00.000Z", end: "2026-11-02T00:00:00.000Z" };
const RUN_AT = Date.UTC(2026, 10, 2, 10, 20);
let tick = 0;
const now = () => new Date(RUN_AT + 1000 * tick++).toISOString();

async function collect(
  t: TempCase,
  session: CloudCollectSession,
  opts: { sources?: readonly CollectSourceInfo[]; source?: string; window?: CollectWindow } = {},
) {
  const source = opts.source ?? GCP_AUDIT_SOURCE;
  const clock = fakeClock(RUN_AT);
  const fs = faultFs();
  await createCollection(
    fs,
    session,
    {
      dir: t.dir,
      collectionId: "cc-test-abc123",
      caseId: "c1",
      accountId: "acct1",
      accountName: "lab",
      provider: "gcp",
      sources: [source],
      window: opts.window ?? WINDOW,
      filters: {},
      companionVersion: "0.0.0-test",
    },
    now,
  );
  const cp = await runCollection(
    { fs, session, importer: pipelineImporter(t), sources: opts.sources ?? GCP_COLLECT_SOURCES, now, clock },
    t.dir,
    { resume: false },
  );
  const manifest = parseManifest(await readFile(collectionPaths(t.dir).manifest, "utf8"));
  return { cp, manifest, clock };
}

const pagesOf = (manifest: ReturnType<typeof parseManifest>) =>
  manifest.entries.filter((e): e is ManifestPage => e.type === "page");

describe("GCP collection through the engine", () => {
  it("saves every entries:list page and imports it into the case, graded by the existing rules", async () => {
    const t = await tempCase();
    const { wire, calls } = mockWire((req) =>
      req.json?.pageToken
        ? { body: { entries: [gcpAuditEntry(3, "google.logging.v2.ConfigServiceV2.DeleteSink")] } }
        : {
            body: {
              entries: [gcpAuditEntry(1, "google.iam.admin.v1.CreateServiceAccountKey"), gcpAuditEntry(2)],
              nextPageToken: "tok-1",
            },
          },
    );
    const { cp, manifest } = await collect(t, gcpCollectSession({ wire, settings: SETTINGS }));
    expect(cp.status).toBe("complete");
    expect(calls.map((c) => c.url)).toEqual([GCP_ENTRIES_LIST_URL, GCP_ENTRIES_LIST_URL]);
    const pages = pagesOf(manifest);
    expect(pages.map((p) => p.records)).toEqual([2, 1]);
    expect(pages[0].requestParams.filter).toContain("cloudaudit.googleapis.com%2Factivity");
    expect(pages[1].pageTokenIn).toBe("tok-1");
    expect(cp.imported).toHaveLength(2);
    const state = await t.stateStore.load("c1");
    const graded = state.forensicTimeline.filter((e) => e.severity !== "Info");
    expect(graded.length).toBeGreaterThan(0);
    expect(JSON.stringify(state.forensicTimeline)).toContain("CreateServiceAccountKey");
    expect(cp.coverage?.[0].notes.join(" ")).toMatch(/Data Access audit logs are OFF by default/);
  });

  it("restarts the sub-window from its start when Google rejects an expired page token", async () => {
    const t = await tempCase();
    let expired = false;
    const { wire, calls } = mockWire((req) => {
      if (req.json?.pageToken === "tok-1" && !expired) {
        expired = true;
        return { status: 400, body: googleError(400, "INVALID_ARGUMENT", "page_token has expired") };
      }
      return req.json?.pageToken
        ? { body: { entries: [gcpAuditEntry(2)] } }
        : { body: { entries: [gcpAuditEntry(1)], nextPageToken: "tok-1" } };
    });
    const { cp, manifest } = await collect(t, gcpCollectSession({ wire, settings: SETTINGS }));
    expect(cp.status).toBe("complete");
    expect(manifest.entries.filter((e) => e.type === "restart")).toEqual([
      expect.objectContaining({ reason: "cursor-expired", subWindowId: `${GCP_AUDIT_SOURCE}:0` }),
    ]);
    // first page, the rejected token, then the sub-window again from its start.
    expect(calls.map((c) => c.json?.pageToken ?? null)).toEqual([null, "tok-1", null, "tok-1"]);
    expect(cp.subWindows[0].restarts).toBe(1);
  });

  it("falls back to one request per logName when a one-second window is still capped", async () => {
    const t = await tempCase();
    const dense = GCP_COLLECT_SOURCES.map((s) => ({ ...s, maxPagesPerWindow: 1 }));
    const { wire, calls } = mockWire((req) => {
      const partitioned = !String(req.json?.filter).includes(" OR ");
      return partitioned
        ? { body: { entries: [gcpAuditEntry(calls.length)] } }
        : { body: { entries: [gcpAuditEntry(0)], nextPageToken: "more" } };
    });
    const oneSecond = { start: "2026-11-01T15:00:00.000Z", end: "2026-11-01T15:00:01.000Z" };
    const { cp, manifest } = await collect(t, gcpCollectSession({ wire, settings: SETTINGS }), {
      sources: dense,
      window: oneSecond,
    });
    const split = manifest.entries.find((e) => e.type === "split");
    expect(split).toMatchObject({ mode: "partition" });
    const logs = calls.slice(1).map((c) => /%2F([a-z_]+)"\)/.exec(String(c.json?.filter))?.[1]);
    expect(logs).toEqual(["activity", "data_access", "system_event", "policy"]);
    expect(cp.status).toBe("complete");
  });

  it("backs off on RESOURCE_EXHAUSTED with Google's Retry-After and retries the same request", async () => {
    const t = await tempCase();
    let throttled = false;
    const { wire, calls } = mockWire(() => {
      if (!throttled) {
        throttled = true;
        return {
          status: 429,
          headers: { "retry-after": "4" },
          body: googleError(429, "RESOURCE_EXHAUSTED", "Quota exceeded for ReadRequestsPerMinutePerProject"),
        };
      }
      return { body: { entries: [gcpAuditEntry(1)] } };
    });
    const { cp, clock } = await collect(t, gcpCollectSession({ wire, settings: SETTINGS }));
    expect(cp.status).toBe("complete");
    expect(calls).toHaveLength(2);
    expect(clock.sleeps).toContain(4000);
  });

  it("discloses a GCS sink's late-shard cutoff in the result, not a five-minute one", async () => {
    const t = await tempCase();
    const name = "cloudaudit.googleapis.com/activity/2026/11/02/06:00:00_06:59:59_S0.json";
    const { wire } = mockWire((req) => {
      const url = new URL(req.url);
      if (url.pathname.endsWith("/sinks"))
        return {
          body: {
            sinks: [
              {
                name: "all-audit",
                destination: "storage.googleapis.com/audit-bucket-01",
                createTime: "2026-01-01T00:00:00Z",
                updateTime: "2026-01-01T00:00:00Z",
              },
            ],
          },
        };
      if (url.searchParams.get("alt") === "media") return { body: JSON.stringify(gcpAuditEntry(7)) + "\n" };
      const prefix = url.searchParams.get("prefix") ?? "";
      return { body: name.startsWith(prefix) ? { items: [{ name }] } : {} };
    });
    const window = { start: "2026-11-02T06:00:00.000Z", end: "2026-11-02T10:00:00.000Z" };
    const session = gcpCollectSession({ wire, settings: SETTINGS, now: () => RUN_AT });
    const { cp, manifest } = await collect(t, session, { source: GCP_SINK_SOURCE, window });
    const [page] = pagesOf(manifest);
    expect(page.requestParams).toMatchObject({ route: "gcs-sink", object: name });
    expect(page.acquiredUntil).toBe(lastCompleteBatchEnd(RUN_AT));
    const coverage = cp.coverage?.find((c) => c.source === GCP_SINK_SOURCE);
    expect(coverage?.acquiredCutoff).toBe("2026-11-02T07:00:00.000Z");
    expect(coverage?.notes.join(" ")).toMatch(/Settled up to 2026-11-02T07:00:00.000Z only/);
    // Sink delivery is not guaranteed: never a plain "complete" on sink pages alone.
    expect(page.unverified).toBe(true);
    expect(cp.status).toBe("partial");
    expect(cp.missing).toEqual([]);
    expect(coverage?.notes).toContain(SINK_UNVERIFIED_NOTE);
    // A resume rebuilds the same verdict from the manifest.
    const again = await runCollection(
      { fs: faultFs(), session, importer: pipelineImporter(t), sources: GCP_COLLECT_SOURCES, now },
      t.dir,
      { resume: true },
    );
    expect(again.status).toBe("partial");
    expect(again.coverage?.[0].notes).toContain(SINK_UNVERIFIED_NOTE);
  });

  it("puts a rejected sink's reason in the result's coverage notes, and the API data completes", async () => {
    const t = await tempCase();
    const { wire } = mockWire((req) => {
      if (new URL(req.url).pathname.endsWith("/sinks"))
        return {
          body: {
            sinks: [
              {
                name: "narrow",
                destination: "storage.googleapis.com/audit-bucket-01",
                filter: 'logName:"cloudaudit.googleapis.com"\nseverity>=ERROR',
              },
            ],
          },
        };
      return { body: { entries: [gcpAuditEntry(1)] } };
    });
    const { cp } = await collect(t, gcpCollectSession({ wire, settings: SETTINGS }), {
      source: GCP_SINK_SOURCE,
    });
    expect(cp.status).toBe("complete");
    expect(cp.coverage?.[0].notes.join(" ")).toContain(
      'Log sink not used: sink "narrow": its filter cannot be proven to keep every audit entry.',
    );
  });
});
