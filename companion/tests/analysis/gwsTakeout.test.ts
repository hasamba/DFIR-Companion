// #931 item 11 (Takeout): the Reports API `takeout` records read for what each states — four
// event-specific schemas — and the job lifecycle joined only by tenant + TAKEOUT_ID across the
// started / completed / downloaded records of one export. No stage the record does not carry.
import { describe, expect, it } from "vitest";
import { parseGoogleWorkspaceReport } from "../../src/analysis/googleWorkspaceImport.js";
import { gwsTakeoutLifecycles, GWS_TAKEOUT_MAX } from "../../src/analysis/gwsTakeout.js";
import {
  canonicalConformanceIssues,
  canonicalEventEnvelopeSchema,
} from "../../src/analysis/canonicalEvent.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const USER = "alice@corp.example";
const JOB = "3f9c2b1a-0000-4000-8000-0123456789ab";
const T = "2026-05-02T10:00:00.000Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
const p = (name: string, value: string | number) =>
  typeof value === "number" ? { name, intValue: String(value) } : { name, value };
const act = (
  name: string,
  params: unknown[],
  over: Record<string, unknown> = {},
): Record<string, unknown> => {
  const { id, ...rest } = over as { id?: Record<string, unknown> } & Record<string, unknown>;
  return {
    kind: "admin#reports#activity",
    id: { time: T, uniqueQualifier: "-1", applicationName: "takeout", customerId: "C01abc", ...(id ?? {}) },
    actor: { email: USER, profileId: "1234" },
    ipAddress: "203.0.113.10",
    events: [{ type: "USER_TAKEOUT", name, parameters: params }],
    ...rest,
  };
};
const started = (over: Record<string, unknown> = {}, job = JOB) =>
  act(
    "STARTED_USER_TAKEOUT",
    [
      p("TAKEOUT_ID", job),
      p("USER_EMAIL", USER),
      p("INITIATED_BY", USER),
      p("PRODUCTS_REQUESTED", "mail, drive"),
      p("TAKEOUT_DESTINATION", "EMAIL"),
      p("START_TIME", 1777716000),
    ],
    over,
  );
const completed = (status = "COMPLETED", over: Record<string, unknown> = {}, job = JOB) =>
  act(
    "COMPLETED_USER_TAKEOUT",
    [
      p("TAKEOUT_ID", job),
      p("USER_EMAIL", USER),
      p("INITIATED_BY", USER),
      p("PRODUCTS_REQUESTED", "mail, drive"),
      p("TAKEOUT_DESTINATION", "EMAIL"),
      p("TAKEOUT_STATUS", status),
      p("COMPLETION_TIME", 1777718520),
    ],
    { id: { time: at(2520) }, ...over },
  );
const downloaded = (over: Record<string, unknown> = {}, job = JOB) =>
  act(
    "DOWNLOADED_USER_TAKEOUT",
    [
      p("TAKEOUT_ID", job),
      p("USER_EMAIL", USER),
      p("PRODUCTS_REQUESTED", "mail, drive"),
      p("DOWNLOAD_TIME", 1777719780),
    ],
    {
      id: { time: at(3780) },
      ...over,
    },
  );
const imported = (records: Record<string, unknown>[], opts: Record<string, unknown> = {}) =>
  parseGoogleWorkspaceReport(JSON.stringify(records), { aggregate: false, ...opts });
const rows = (records: Record<string, unknown>[]) =>
  gwsTakeoutLifecycles(records).filter((e) => e.description.startsWith("Google Workspace Takeout job:"));

describe("Takeout records — four event-specific schemas", () => {
  it("a started record reads as requested, with the job, the target user, the literal initiator, the products, the destination as recorded and the integer time as recorded", () => {
    const e = imported([started()]).events[0];
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toContain("T1530");
    expect(e.description).toContain("Google Workspace takeout: STARTED_USER_TAKEOUT by alice@corp.example");
    expect(e.description).toContain(`Takeout requested — job ${JOB}`);
    expect(e.description).toContain(
      "target user alice@corp.example; initiated by (as recorded) alice@corp.example; products mail, drive; destination recorded as EMAIL (a download link); START_TIME 1777716000 (as recorded)",
    );
    expect(e.description).not.toMatch(/2026-05-0[0-9]T.*START_TIME/);
    expect(e.timestamp).toBe(T);
    const env = canonicalEventEnvelopeSchema.parse(e.canonical);
    expect(env.event).toEqual({
      category: "cloud",
      type: "takeout",
      action: "STARTED_USER_TAKEOUT",
      outcome: "success",
    });
    expect(env.cloud?.resource).toBe(JOB);
    expect(env.takeout).toMatchObject({
      stage: "requested",
      jobId: JOB,
      userEmail: USER,
      initiatedBy: USER,
      destination: "EMAIL",
      products: ["mail", "drive"],
      startTime: "1777716000",
    });
    expect(canonicalConformanceIssues(env)).toEqual([]);
  });

  it("initiated-by, the target user and the audit actor are three independent facts — no delegation is inferred", () => {
    const e = imported([
      act(
        "STARTED_USER_TAKEOUT",
        [
          p("TAKEOUT_ID", JOB),
          p("USER_EMAIL", USER),
          p("INITIATED_BY", "ADMIN"),
          p("PRODUCTS_REQUESTED", "drive"),
        ],
        { actor: { email: "admin@corp.example", profileId: "99" } },
      ),
    ]).events[0];
    expect(e.description).toContain("by admin@corp.example");
    expect(e.description).toContain("target user alice@corp.example; initiated by (as recorded) ADMIN");
    expect(e.description).not.toMatch(/on behalf|for another|delegat/);
  });

  it("a completed record reads its status: COMPLETED is prepared (Medium); FAILED / CANCELED / IN_PROGRESS are quoted and Low", () => {
    const ok = imported([completed()]).events[0];
    expect(ok.severity).toBe("Medium");
    expect(ok.description).toContain(`Takeout prepared — job ${JOB} — status COMPLETED`);
    expect(ok.description).toContain("COMPLETION_TIME 1777718520 (as recorded)");
    const failed = imported([completed("FAILED")]).events[0];
    expect(failed.severity).toBe("Low");
    expect(failed.description).toContain("Takeout not prepared — job");
    expect(failed.description).toContain("status FAILED");
    expect(imported([completed("IN_PROGRESS")]).events[0].description).toContain("status IN_PROGRESS");
  });

  it("a downloaded record is 'download started' and High; a scheduled record is periodic, carries no job id, and is narrated literally", () => {
    const dl = imported([downloaded()]).events[0];
    expect(dl.severity).toBe("High");
    expect(dl.mitreTechniques).toContain("T1530");
    expect(dl.description).toContain(`Takeout download started — job ${JOB}`);
    expect(dl.description).toContain("DOWNLOAD_TIME 1777719780 (as recorded)");
    const sched = imported([
      act("SCHEDULED_USER_TAKEOUT", [
        p("USER_EMAIL", USER),
        p("PRODUCTS_REQUESTED", "drive"),
        p("TAKEOUT_DESTINATION", "DRIVE"),
        p("TAKEOUT_INTERVAL_UNITS", "MONTH"),
        p("TAKEOUT_INTERVAL_VALUE", 2),
        p("SCHEDULED_TAKEOUT_EXPIRATION", 1809252000),
        p("TAKEOUT_STATUS", "IN_PROGRESS"),
      ]),
    ]).events[0];
    expect(sched.severity).toBe("Medium");
    expect(sched.description).toContain(
      "periodic Takeout scheduled — every 2 MONTH; expiration 1809252000 (as recorded); status IN_PROGRESS",
    );
    expect(sched.description).toContain("destination recorded as DRIVE");
    expect(sched.description).not.toContain("job");
    expect(canonicalEventEnvelopeSchema.parse(sched.canonical).takeout?.stage).toBe("scheduled");
  });

  it("two jobs' records are two rows; one job's records are distinct stages, never folded; a record with no job id keys on its locator", () => {
    const r = imported([started(), started({}, "other-job"), completed(), downloaded()], { aggregate: true });
    expect(r.events.filter((e) => e.description.startsWith("Google Workspace takeout:"))).toHaveLength(4);
    const noJob = imported(
      [
        act("STARTED_USER_TAKEOUT", [p("USER_EMAIL", USER)]),
        act("STARTED_USER_TAKEOUT", [p("USER_EMAIL", USER)]),
      ],
      { aggregate: true },
    );
    expect(noJob.events.filter((e) => e.description.startsWith("Google Workspace takeout:"))).toHaveLength(2);
    expect(noJob.events[0].description).toContain("job id not in this record");
  });
});

describe("gwsTakeoutLifecycles — one job, three stages, joined by tenant + TAKEOUT_ID", () => {
  it("requested → prepared → download started, each from its own record; the destination is a recorded setting, never a transfer", () => {
    const [row] = rows([started(), completed(), downloaded()]);
    expect(row.severity).toBe("High");
    expect(row.mitre).toContain("T1530");
    expect(row.description).toContain(
      `Google Workspace Takeout job: ${JOB} (target user alice@corp.example)`,
    );
    expect(row.description).toContain(
      "requested 2026-05-02T10:00:00.000Z by alice@corp.example (record:0/event:0) — products mail, drive; destination recorded as EMAIL (a download link); initiated by (as recorded) alice@corp.example",
    );
    expect(row.description).toContain(
      "prepared 2026-05-02T10:42:00.000Z — status COMPLETED (record:1/event:0)",
    );
    expect(row.description).toContain(
      "download started 2026-05-02T11:03:00.000Z by alice@corp.example (record:2/event:0)",
    );
    expect(row.description).not.toMatch(/transferred|delivered|exfiltrat/);
    expect(row.description).toContain("Takeout audit retention is not in this evidence");
    expect(row.timestamp).toBe(T);
    const env = canonicalEventEnvelopeSchema.parse(row.canonical);
    expect(env.event).toEqual({
      category: "cloud",
      type: "takeout-lifecycle",
      action: "lifecycle",
      outcome: "success",
    });
    expect(env.takeoutLifecycle).toMatchObject({ jobId: JOB, userEmail: USER, destination: "EMAIL" });
    expect(env.takeoutLifecycle?.requested?.locator).toBe("record:0/event:0");
    expect(env.takeoutLifecycle?.downloaded?.locator).toBe("record:2/event:0");
    expect(env.evidence.rawRecords.map((r) => r.locator)).toEqual([
      "record:0/event:0",
      "record:1/event:0",
      "record:2/event:0",
    ]);
  });

  it("a missing stage reads as absent with the export's own count; a failed completion is not prepared; requested alone is Medium; download alone is High", () => {
    const [requestedOnly] = rows([
      started(),
      act("STARTED_USER_TAKEOUT", [p("TAKEOUT_ID", "x-1"), p("USER_EMAIL", USER)], { id: { time: at(60) } }),
    ]);
    expect(requestedOnly.severity).toBe("Medium");
    expect(requestedOnly.description).toContain("no prepared record in this export");
    expect(requestedOnly.description).toContain(
      "no download record in this export (2 records of this export, 2026-05-02T10:00:00Z → 2026-05-02T10:01:00Z)",
    );
    expect(requestedOnly.description).toContain("requested; not shown to be prepared or downloaded");
    const [failed] = rows([started(), completed("FAILED")]);
    expect(failed.severity).toBe("Low");
    expect(failed.description).toContain(
      "completion recorded 2026-05-02T10:42:00.000Z — status FAILED, not prepared (record:1/event:0)",
    );
    const [dlOnly] = rows([downloaded()]);
    expect(dlOnly.severity).toBe("High");
    expect(dlOnly.description).toContain("no requested record in this export");
    expect(dlOnly.description).toContain("download started 2026-05-02T11:03:00.000Z");
  });

  it("a scheduled record never joins a job; a Drive record about a folder named Takeout is never a stage; another tenant's job with the same id is another row", () => {
    const sched = act("SCHEDULED_USER_TAKEOUT", [
      p("USER_EMAIL", USER),
      p("PRODUCTS_REQUESTED", "drive"),
      p("TAKEOUT_DESTINATION", "DRIVE"),
    ]);
    const driveFolder = {
      ...act(
        "create",
        [
          { name: "doc_id", value: "1x" },
          { name: "doc_title", value: "Takeout" },
          { name: "doc_type", value: "folder" },
        ],
        { id: { applicationName: "drive", time: at(4000) } },
      ),
      events: [
        {
          type: "access",
          name: "create",
          parameters: [
            { name: "doc_id", value: "1x" },
            { name: "doc_title", value: "Takeout" },
          ],
        },
      ],
    };
    const out = rows([sched, started(), driveFolder]);
    expect(out).toHaveLength(1);
    expect(out[0].description).not.toContain("folder");
    expect(out[0].description).not.toContain("scheduled");
    expect(rows([started(), started({ id: { customerId: "C02xyz" } })])).toHaveLength(2);
    expect(rows([sched])).toHaveLength(0);
  });

  it("the earliest record supplies the display facts whatever the file order; ids are deterministic; a re-import folds; hostile values are neutralised", () => {
    const a = rows([downloaded(), completed(), started()]);
    const b = rows([started(), completed(), downloaded()]);
    const norm = (d: string) => d.replace(/record:\d+/g, "record:x");
    expect(norm(a[0].description)).toBe(norm(b[0].description));
    expect(a[0].aggKey).toBe(b[0].aggKey);
    expect(a[0].aggKey).toMatch(/^gws-takeout-job\|[0-9a-f]{32}$/);
    const asEvents = (tag: string): ForensicEvent[] =>
      imported([started(), completed(), downloaded()])
        .events.filter((e) => e.description.startsWith("Google Workspace Takeout job:"))
        .map((e, i) => ({
          ...e,
          id: `${tag}-${i}`,
          relatedFindingIds: [],
          sourceScreenshots: [],
          sources: ["Google Workspace"],
        }));
    expect(correlateEvents([...asEvents("a"), ...asEvents("b")])).toHaveLength(1);
    const evil = act("STARTED_USER_TAKEOUT", [
      p("TAKEOUT_ID", "job] [fake: downloaded"),
      p("USER_EMAIL", "u] [x@corp.example\u202e"),
      p("INITIATED_BY", "=CMD()|x"),
      p("PRODUCTS_REQUESTED", "mail] [drive"),
      p("TAKEOUT_DESTINATION", "EMAIL] [BOX"),
    ]);
    const [row] = rows([evil]);
    for (const s of [row.description]) {
      expect(s).not.toContain("] [");
      expect(s).not.toContain("\u202e");
    }
    expect(row.description).toContain("destination recorded as EMAIL) (BOX (not a documented value)");
  });

  it("257 jobs → 256 rows and an omitted row; the importer appends the rows after the source-row cap and counts source rows alone", () => {
    const many = Array.from({ length: GWS_TAKEOUT_MAX + 1 }, (_, i) =>
      started({ id: { time: at(i) } }, `job-${i}`),
    );
    const out = gwsTakeoutLifecycles(many);
    expect(out.filter((e) => e.description.startsWith("Google Workspace Takeout job:"))).toHaveLength(
      GWS_TAKEOUT_MAX,
    );
    expect(out.find((e) => e.description.includes("further job"))?.description).toContain(
      `1 further job with records in this export beyond the ${GWS_TAKEOUT_MAX} reported — not shown`,
    );
    const r = imported([started(), completed(), downloaded()], { maxEvents: 1 });
    const lifecycle = r.events.filter((e) => e.description.startsWith("Google Workspace Takeout job:"));
    expect(lifecycle).toHaveLength(1);
    expect(r.kept).toBe(1);
    expect(r.summaries).toBe(1);
    expect(r.dropped).toBe(2);
    expect(lifecycle[0].canonical?.evidence.sourceArtifactHash).toMatch(/^sha256:/);
  });
});
