import { test, expect } from "../fixtures/test.js";
import type { APIRequestContext } from "@playwright/test";

// Covers: US-056, US-057, US-059, US-061, US-062, US-063, US-064, US-065, US-067, US-068
// Covers: US-071, US-072, US-073, US-074, US-141, US-146, US-149, US-150, US-155, US-172
// (feature-user-stories.csv) — the dashboard panels whose content comes from a case-scoped
// endpoint: attack phases, timeline gaps, the asset graph, beacons, IOCs, customer exposure, key
// questions, hunting profile, ATT&CK, adversary hints, playbook, notebook, investigation log, case
// details, mobile summary, geo map, false positives, pinned findings, super timeline and evidence
// gaps.
//
// Each row asserts SUBSTANCE, not a status code. Every one of these panels renders whatever its
// endpoint returns, so a 200 carrying an empty object paints an empty panel and looks like "this
// case has no beacons" rather than "the derivation broke". The seeded case has known content —
// 59 events, 14 findings, 17 IOCs, fixed hosts — so the assertions can name it.
//
// Where a panel is legitimately empty for the demo case (no hunts have been run, no findings
// pinned, no activity logged yet) the row asserts the CONTRACT instead, and says so. Asserting
// non-empty there would be asserting the fixture, not the product.

interface PanelCase {
  story: string;
  path: string;
  /** Throws with a useful message if the payload is not what the panel needs. */
  check: (body: unknown) => void;
}

const asArray = (body: unknown): unknown[] => {
  expect(Array.isArray(body), `expected an array, got ${typeof body}`).toBe(true);
  return body as unknown[];
};

const asRecord = (body: unknown): Record<string, unknown> => {
  expect(typeof body === "object" && body !== null, "expected an object").toBe(true);
  return body as Record<string, unknown>;
};

const PANELS: readonly PanelCase[] = [
  {
    story: "US-056",
    path: "phases",
    check: (b) => {
      const rows = asArray(b);
      expect(rows.length, "attack phases were derived from 58 events").toBeGreaterThan(0);
      // Phases are labelled by dominant tactic; an unlabelled phase is an empty row on the panel.
      expect(JSON.stringify(rows)).toContain("Initial Access");
    },
  },
  {
    story: "US-057",
    path: "timeline-gaps",
    check: (b) => {
      const rows = asArray(b);
      expect(rows.length, "the seeded timeline contains a deliberate multi-hour gap").toBeGreaterThan(0);
      expect(asRecord(rows[0])).toHaveProperty("startTimestamp");
    },
  },
  {
    story: "US-059",
    path: "asset-graph",
    check: (b) => {
      const assets = asRecord(b).assets as unknown[];
      expect(assets?.length, "compromised hosts and accounts drive this graph").toBeGreaterThan(0);
      // The graph's whole point is linking assets to the IOCs that touched them.
      expect(JSON.stringify(assets)).toContain("iocIds");
    },
  },
  {
    story: "US-061",
    path: "beacon-candidates",
    check: (b) => {
      const rows = asArray(b);
      expect(rows.length, "the seeded case has a periodic C2 channel").toBeGreaterThan(0);
      expect(JSON.stringify(rows)).toContain("intervalSec");
    },
  },
  {
    story: "US-063",
    path: "customer-exposure",
    check: (b) => {
      const rec = asRecord(b);
      expect(rec).toHaveProperty("targets");
      expect(rec).toHaveProperty("providers");
    },
  },
  {
    story: "US-065",
    path: "hunt-outcomes",
    check: (b) => {
      // Contract only: no hunts have been run against the demo case, so hunts[] is correctly empty.
      const rec = asRecord(b);
      for (const k of ["total", "hit", "missed", "pending"]) expect(rec).toHaveProperty(k);
      expect(Array.isArray(rec.hunts)).toBe(true);
    },
  },
  {
    story: "US-067",
    path: "attack-mitigations",
    check: (b) => {
      const rec = asRecord(b);
      // The bundled ATT&CK dataset must actually load; without it the panel silently shows nothing.
      expect(rec.attackVersion, "bundled ATT&CK dataset version").toBeTruthy();
    },
  },
  {
    story: "US-068",
    path: "adversary-hints",
    check: (b) => {
      const rec = asRecord(b);
      expect(Number(rec.groupCount), "ATT&CK groups loaded").toBeGreaterThan(0);
      expect(Number(rec.caseTechniqueCount), "techniques found in this case").toBeGreaterThan(0);
    },
  },
  {
    story: "US-071",
    path: "playbook",
    check: (b) => {
      const tasks = asRecord(b).tasks as unknown[];
      expect(tasks?.length, "the seeded case's next steps become playbook tasks").toBeGreaterThan(0);
    },
  },
  {
    story: "US-072",
    path: "notebook",
    check: (b) => {
      const rows = asArray(b);
      expect(rows.length, "the seeded case ships analyst notes").toBeGreaterThan(0);
      expect(asRecord(rows[0])).toHaveProperty("text");
    },
  },
  {
    story: "US-073",
    path: "activity-log",
    check: (b) => {
      // Contract only: nothing has been done to the demo case in this run, so the log is correctly
      // empty. What matters is that it answers with a list rather than 404ing the panel.
      asArray(b);
    },
  },
  {
    story: "US-074",
    path: "report-meta",
    check: (b) => {
      const rec = asRecord(b);
      // These fields feed the report title page; blank ones ship an unlabelled report.
      expect(rec.organization, "organization feeds the report title page").toBeTruthy();
    },
  },
  {
    story: "US-141",
    path: "mobile-summary",
    check: (b) => {
      const rec = asRecord(b);
      expect(rec.caseId).toBeTruthy();
      expect(rec.caseName, "the mobile view leads with the case name").toBeTruthy();
    },
  },
  {
    story: "US-146",
    path: "geo-map",
    check: (b) => {
      const stats = asRecord(asRecord(b).stats ?? {});
      // markers[] is empty without network geolocation, which the suite must not depend on. The
      // derivation still has to find the IPs to resolve — that part is offline and testable.
      expect(Number(stats.totalIps), "external IPs found in the case's IOCs").toBeGreaterThan(0);
    },
  },
  {
    story: "US-149",
    path: "false-positive",
    check: (b) => {
      const rows = asArray(b);
      expect(rows.length, "the seeded case marks a known-good DNS server").toBeGreaterThan(0);
      expect(asRecord(rows[0])).toHaveProperty("reason");
    },
  },
  {
    story: "US-150",
    path: "pinned-findings",
    check: (b) => {
      // Contract only: nothing is pinned in a fresh case. The limit is what the panel enforces.
      const rec = asRecord(b);
      expect(Array.isArray(rec.pins)).toBe(true);
      expect(Number(rec.limit)).toBeGreaterThan(0);
    },
  },
  {
    story: "US-155",
    path: "super-timeline",
    check: (b) => {
      const events = asRecord(b).events as unknown[];
      expect(events?.length, "the merged super-timeline carries the seeded events").toBeGreaterThan(0);
    },
  },
  {
    story: "US-172",
    path: "known-unknowns",
    check: (b) => {
      const items = asRecord(b).items as unknown[];
      expect(items?.length, "structured evidence gaps for the seeded case").toBeGreaterThan(0);
      // Each gap must carry the tactic it is about, or it is not actionable.
      expect(JSON.stringify(items)).toContain("tactic");
    },
  },
];

for (const panel of PANELS) {
  test(`${panel.story}: /${panel.path} returns data the panel can render`, async ({ page, demoCase }) => {
    await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

    const res = await page.request.get(`/cases/${demoCase}/${panel.path}`);
    expect(res.status(), await res.text()).toBe(200);
    panel.check(await res.json());
  });
}

/** The two panels that read straight from case state rather than their own endpoint. */
async function state(request: APIRequestContext, caseId: string): Promise<Record<string, unknown>> {
  const res = await request.get(`/cases/${caseId}/state`);
  expect(res.status()).toBe(200);
  return (await res.json()) as Record<string, unknown>;
}

test("US-062: the IOC panel's source data carries verdicts", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  const iocs = (await state(page.request, demoCase)).iocs as unknown[];
  expect(iocs?.length, "the seeded case has 17 IOCs").toBeGreaterThan(0);
  // The field is `type`, not `kind` — the story's prose says "by kind", the data says type.
  // Grouping is how the panel renders, so an IOC without it cannot be placed.
  const first = iocs[0] as Record<string, unknown>;
  expect(first).toHaveProperty("type");
  expect(first).toHaveProperty("value");
  // "verdicts/enrichments" is the column that makes the panel worth reading.
  expect(JSON.stringify(iocs)).toContain("enrichments");
});

test("US-064: key questions come from synthesis with their status", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  const questions = (await state(page.request, demoCase)).keyQuestions as unknown[];
  expect(questions?.length, "synthesis produced key questions").toBeGreaterThan(0);
  // A question with no status cannot show whether it is answered, which is the panel's only job.
  expect(JSON.stringify(questions)).toContain("status");
});
