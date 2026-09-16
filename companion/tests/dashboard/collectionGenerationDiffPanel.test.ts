// #1128/#1132: the collection-generation-diff panel — persistence + mobile halves, independent
// loading/ready/unconfigured/error state, and the minimal mobile recording flow.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  renderCollectionGenerationDiff(): string;
  loadCollectionGenerationDiff(caseId: string): Promise<void>;
}

type Responder = (url: string) => { ok: boolean; status?: number; json?: () => Promise<unknown> };

function panelWith(respond: Responder) {
  return loadDashboardModule<Api>("dashboard-collection-generation-diff.js", ["dashboard-escape.js"], {
    fetch: async (url: string) => {
      const r = respond(url);
      return { ok: r.ok, status: r.status ?? (r.ok ? 200 : 500), json: r.json ?? (async () => ({})) };
    },
    document: { getElementById: () => null }, // paint() no-ops without the panel element
  });
}

async function panel(persistenceBody: unknown, mobileBody: unknown): Promise<Api> {
  const p = panelWith((url) => ({
    ok: true,
    json: async () => (url.includes("mobile-backup-generations") ? mobileBody : persistenceBody),
  }));
  await p.loadCollectionGenerationDiff("c1");
  return p;
}

const PERSISTENCE_PAIR = {
  resolvedHost: "ws-01",
  eligibleCount: 2,
  excluded: [],
  ambiguousOrder: [],
  truncatedPairs: false,
  pairs: [
    {
      earlier: { order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" } },
      later: { order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" } },
      interveningExcludedCount: 0,
      truncated: false,
      inventoryTruncated: false,
      changes: [
        {
          direction: "changed",
          key: JSON.stringify(["Run Key", "HKCU\\Run\\A"]),
          earlierValue: "old.exe",
          laterValue: "new.exe",
        },
      ],
    },
  ],
};

const MOBILE_PAIR = {
  resolvedDevice: { kind: "serial-number", value: "F2LN12ABCDEF" },
  eligibleCount: 2,
  excluded: [],
  ambiguousOrder: [],
  truncatedPairs: false,
  pairs: [
    {
      earlier: { order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" } },
      later: { order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" } },
      interveningExcludedCount: 0,
      truncated: false,
      inventoryTruncated: false,
      changes: [
        {
          direction: "changed",
          key: "com.example.app",
          earlierValue: { itemName: "Example", version: "1.0" },
          laterValue: { itemName: "Example", version: "2.0" },
        },
      ],
    },
  ],
};

describe("collection generation diff panel — persistence + mobile", () => {
  it("renders both a Persistence and a Mobile backups sub-heading", async () => {
    const html = (await panel({ cohorts: [] }, { cohorts: [] })).renderCollectionGenerationDiff();
    expect(html).toContain("Persistence");
    expect(html).toContain("Mobile backups");
  });

  it("renders a persistence pair's technique/path/value change", async () => {
    const html = (
      await panel({ cohorts: [PERSISTENCE_PAIR] }, { cohorts: [] })
    ).renderCollectionGenerationDiff();
    expect(html).toContain("ws-01");
    expect(html).toContain("Run Key");
    expect(html).toContain("HKCU\\Run\\A");
    expect(html).toContain("old.exe");
    expect(html).toContain("new.exe");
  });

  it("renders a mobile pair's bundle id/item/version change, never as [object Object]", async () => {
    const html = (await panel({ cohorts: [] }, { cohorts: [MOBILE_PAIR] })).renderCollectionGenerationDiff();
    expect(html).toContain("com.example.app");
    expect(html).toContain("Example");
    expect(html).toContain("1.0");
    expect(html).toContain("2.0");
    expect(html).not.toContain("[object Object]");
  });

  it("a mobile fetch failure never hides a valid persistence result", async () => {
    const p = panelWith((url) =>
      url.includes("mobile-backup-generations")
        ? { ok: false, status: 500 }
        : { ok: true, json: async () => ({ cohorts: [PERSISTENCE_PAIR] }) },
    );
    await p.loadCollectionGenerationDiff("c1");
    const html = p.renderCollectionGenerationDiff();
    expect(html).toContain("ws-01"); // persistence result still rendered
    expect(html).toContain("Could not load the mobile backup comparison");
  });

  it("a persistence fetch failure never hides a valid mobile result", async () => {
    const p = panelWith((url) =>
      url.includes("mobile-backup-generations")
        ? { ok: true, json: async () => ({ cohorts: [MOBILE_PAIR] }) }
        : { ok: false, status: 500 },
    );
    await p.loadCollectionGenerationDiff("c1");
    const html = p.renderCollectionGenerationDiff();
    expect(html).toContain("com.example.app"); // mobile result still rendered
    expect(html).toContain("Could not load the persistence comparison");
  });

  it("501 on either route renders an honest 'not configured' state, not an error", async () => {
    const p = panelWith(() => ({ ok: false, status: 501 }));
    await p.loadCollectionGenerationDiff("c1");
    const html = p.renderCollectionGenerationDiff();
    expect(html).not.toContain("Could not load");
    expect(html).toContain("No host has two or more");
    expect(html).toContain("No device has two or more");
  });

  it("shows the record-pairing button in the mobile section", async () => {
    const html = (await panel({ cohorts: [] }, { cohorts: [] })).renderCollectionGenerationDiff();
    expect(html).toContain("Record a backup pairing");
  });
});

interface RecordApi extends Api {
  openRecordForm(caseId: string): Promise<void>;
  closeRecordForm(): void;
  submitRecordForm(caseId: string, el: unknown): Promise<void>;
}

const NO_DATE_BACKUP_CANDIDATE = {
  importSeq: 1,
  originalName: "backup.tsv",
  importedAt: "2026-01-12T09:00:00Z",
  looksLike: "backup-info",
  preview: { kind: "backup-info", deviceIdentity: { kind: "serial-number", value: "X" }, capturedAt: "" },
};

const DATED_BACKUP_CANDIDATE = {
  ...NO_DATE_BACKUP_CANDIDATE,
  preview: { ...NO_DATE_BACKUP_CANDIDATE.preview, capturedAt: "2026-01-12T09:00:00Z" },
};

const APPS_CANDIDATE = {
  importSeq: 2,
  originalName: "apps.tsv",
  importedAt: "2026-01-12T09:01:00Z",
  looksLike: "installed-apps",
  preview: { kind: "installed-apps", appCount: 1 },
};

/** A minimal, purpose-built form-field lookup — real enough for submitRecordForm's own
 * `el.querySelector('[data-cgd-field="x"]').value` calls, without a full DOM. */
function fakeForm(values: Record<string, string>) {
  return {
    querySelector: (sel: string) => {
      const m = /data-cgd-field="([^"]+)"/.exec(sel);
      const name = m ? m[1] : "";
      return { value: values[name] ?? "" };
    },
  };
}

describe("collection generation diff panel — mobile recording flow (#1138 code-review fixes)", () => {
  it("openRecordForm ignores a candidate response superseded by a case switch", async () => {
    let resolveFirst: (v: unknown) => void = () => {};
    const first = new Promise((resolve) => {
      resolveFirst = resolve;
    });
    let call = 0;
    const p = loadDashboardModule<RecordApi>(
      "dashboard-collection-generation-diff.js",
      ["dashboard-escape.js"],
      {
        fetch: async (url: string) => {
          if (url.includes("candidate-imports")) {
            call += 1;
            if (call === 1) {
              await first; // case A's own candidate fetch hangs until released below
              return {
                ok: true,
                status: 200,
                json: async () => ({ candidates: [NO_DATE_BACKUP_CANDIDATE] }),
              };
            }
            return { ok: true, status: 200, json: async () => ({ candidates: [APPS_CANDIDATE] }) };
          }
          return { ok: true, status: 200, json: async () => ({ cohorts: [] }) };
        },
        document: { getElementById: () => null },
      },
    );
    const formA = p.openRecordForm("case-a"); // starts, then hangs on `first`
    await p.loadCollectionGenerationDiff("case-b"); // switches case, invalidating A's own token
    resolveFirst(undefined); // let case A's stale fetch resolve now
    await formA;
    const html = p.renderCollectionGenerationDiff();
    // Case A's own stale candidate must never appear — the form should read as freshly closed by
    // the case switch (mFormOpen reset to false), showing the "+ Record" button, not A's dropdown.
    expect(html).toContain("+ Record a backup pairing");
    expect(html).not.toContain("backup.tsv");
  });

  it("submitRecordForm refuses to fire when the active case no longer matches the loaded candidates", async () => {
    let posted = false;
    const p = loadDashboardModule<RecordApi>(
      "dashboard-collection-generation-diff.js",
      ["dashboard-escape.js"],
      {
        fetch: async (url: string, init?: { method?: string }) => {
          if (init?.method === "POST") posted = true;
          if (url.includes("candidate-imports")) {
            return {
              ok: true,
              status: 200,
              json: async () => ({ candidates: [DATED_BACKUP_CANDIDATE, APPS_CANDIDATE] }),
            };
          }
          return { ok: true, status: 200, json: async () => ({ cohorts: [] }) };
        },
        document: { getElementById: () => null },
        alert: () => {},
        confirm: () => true,
      },
    );
    await p.loadCollectionGenerationDiff("case-a");
    await p.openRecordForm("case-a");
    // The analyst switches cases WITHOUT closing the form first (loadCollectionGenerationDiff
    // itself resets mFormOpen, but this simulates a direct submit call racing that reset).
    await p.submitRecordForm(
      "case-b",
      fakeForm({ backupInfoImportSeq: "1", installedAppsImportSeq: "2", completenessState: "complete" }),
    );
    expect(posted).toBe(false);
  });

  it("submitRecordForm refuses a no-date candidate without both declaredSequence and dateUnavailableReason", async () => {
    let posted = false;
    const p = loadDashboardModule<RecordApi>(
      "dashboard-collection-generation-diff.js",
      ["dashboard-escape.js"],
      {
        fetch: async (url: string, init?: { method?: string }) => {
          if (init?.method === "POST") posted = true;
          if (url.includes("candidate-imports")) {
            return {
              ok: true,
              status: 200,
              json: async () => ({ candidates: [NO_DATE_BACKUP_CANDIDATE, APPS_CANDIDATE] }),
            };
          }
          return { ok: true, status: 200, json: async () => ({ cohorts: [] }) };
        },
        document: { getElementById: () => null },
        alert: () => {},
        confirm: () => true,
      },
    );
    await p.loadCollectionGenerationDiff("c1");
    await p.openRecordForm("c1");
    await p.submitRecordForm(
      "c1",
      fakeForm({ backupInfoImportSeq: "1", installedAppsImportSeq: "2", completenessState: "complete" }),
    );
    expect(posted).toBe(false);
  });

  it("submitRecordForm posts declaredSequence/dateUnavailableReason for a no-date candidate that supplies both", async () => {
    let body: Record<string, unknown> | null = null;
    const p = loadDashboardModule<RecordApi>(
      "dashboard-collection-generation-diff.js",
      ["dashboard-escape.js"],
      {
        fetch: async (url: string, init?: { method?: string; body?: string }) => {
          if (init?.method === "POST") body = JSON.parse(init.body || "{}");
          if (url.includes("candidate-imports")) {
            return {
              ok: true,
              status: 200,
              json: async () => ({ candidates: [NO_DATE_BACKUP_CANDIDATE, APPS_CANDIDATE] }),
            };
          }
          return { ok: true, status: 200, json: async () => ({ cohorts: [] }) };
        },
        document: { getElementById: () => null },
        alert: () => {},
        confirm: () => true,
      },
    );
    await p.loadCollectionGenerationDiff("c1");
    await p.openRecordForm("c1");
    await p.submitRecordForm(
      "c1",
      fakeForm({
        backupInfoImportSeq: "1",
        installedAppsImportSeq: "2",
        completenessState: "complete",
        declaredSequence: "1",
        dateUnavailableReason: "no date in export",
      }),
    );
    expect(body).toEqual({
      backupInfoImportSeq: 1,
      installedAppsImportSeq: 2,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: true,
      declaredSequence: 1,
      dateUnavailableReason: "no date in export",
    });
  });

  it("submitRecordForm posts without declaredSequence/dateUnavailableReason for a dated candidate", async () => {
    let body: Record<string, unknown> | null = null;
    const p = loadDashboardModule<RecordApi>(
      "dashboard-collection-generation-diff.js",
      ["dashboard-escape.js"],
      {
        fetch: async (url: string, init?: { method?: string; body?: string }) => {
          if (init?.method === "POST") body = JSON.parse(init.body || "{}");
          if (url.includes("candidate-imports")) {
            return {
              ok: true,
              status: 200,
              json: async () => ({ candidates: [DATED_BACKUP_CANDIDATE, APPS_CANDIDATE] }),
            };
          }
          return { ok: true, status: 200, json: async () => ({ cohorts: [] }) };
        },
        document: { getElementById: () => null },
        alert: () => {},
        confirm: () => true,
      },
    );
    await p.loadCollectionGenerationDiff("c1");
    await p.openRecordForm("c1");
    await p.submitRecordForm(
      "c1",
      fakeForm({ backupInfoImportSeq: "1", installedAppsImportSeq: "2", completenessState: "complete" }),
    );
    expect(body).toEqual({
      backupInfoImportSeq: 1,
      installedAppsImportSeq: 2,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: true,
    });
  });

  it("never uses added/removed/deleted labels for either domain", async () => {
    const html = (
      await panel({ cohorts: [PERSISTENCE_PAIR] }, { cohorts: [MOBILE_PAIR] })
    ).renderCollectionGenerationDiff();
    expect(html).not.toMatch(/\badded\b|\bremoved\b|\bdeleted\b/i);
  });
});
