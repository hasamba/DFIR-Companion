import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Both Timesketch JSONL downloads leave out rows with no parseable time (the format requires one).
// The downloads stay plain navigations so the browser streams them; the count of what they leave
// out comes from GET /timesketch-omitted, which the dashboard asks just before, so the analyst is
// told instead of the file shrinking in silence (#957). The rows themselves stay in the Companion.
function ev(
  p: Partial<ForensicEvent> & Pick<ForensicEvent, "id" | "timestamp" | "description">,
): ForensicEvent {
  return { severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...p };
}

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-ts-jsonl-"));
  const cases = new CaseStore(root);
  const stateStore = new StateStore(cases);
  const superTimelineStore = new SuperTimelineStore(cases);
  const reportWriter = new ReportWriter(cases, stateStore);
  const app = createApp(cases, { stateStore, superTimelineStore, reportWriter });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const rows = [
    ev({ id: "d", timestamp: "2026-05-26T12:00:00Z", description: "dated", severity: "High" }),
    ev({ id: "u1", timestamp: "", description: "undated one", severity: "High" }),
    ev({ id: "u2", timestamp: "", description: "undated two", severity: "High" }),
  ];
  const state = await stateStore.load("c1");
  await stateStore.save({ ...state, forensicTimeline: rows });
  await superTimelineStore.append("c1", rows);
  return { app };
}

describe("Timesketch omission preview (#957)", () => {
  it("forensic scope counts what /timeline.jsonl leaves out", async () => {
    const { app } = await harness();
    const preview = await request(app).get("/cases/c1/timesketch-omitted?scope=forensic");
    expect(preview.status).toBe(200);
    expect(preview.body).toEqual({ scope: "forensic", events: 1, omitted: 2 });
    const file = await request(app).get("/cases/c1/timeline.jsonl");
    const lines = file.text
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as { message: string });
    expect(lines.map((l) => l.message)).toEqual(["dated"]);
  });

  it("super scope counts what /super-timeline.jsonl leaves out", async () => {
    const { app } = await harness();
    const preview = await request(app).get("/cases/c1/timesketch-omitted?scope=super");
    expect(preview.status).toBe(200);
    expect(preview.body).toEqual({ scope: "super", events: 1, omitted: 2 });
    const file = await request(app).get("/cases/c1/super-timeline.jsonl");
    const lines = file.text
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as { message: string });
    expect(lines.map((l) => l.message)).toEqual(["dated"]);
  });

  it("says zero when nothing would be left out, and 501 when the scope's store is not wired", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-ts-jsonl-zero-"));
    const cases = new CaseStore(root);
    const stateStore = new StateStore(cases);
    const reportWriter = new ReportWriter(cases, stateStore);
    const app = createApp(cases, { stateStore, reportWriter });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const state = await stateStore.load("c1");
    await stateStore.save({
      ...state,
      forensicTimeline: [ev({ id: "d", timestamp: "2026-05-26T12:00:00Z", description: "dated" })],
    });
    const forensic = await request(app).get("/cases/c1/timesketch-omitted");
    expect(forensic.body).toEqual({ scope: "forensic", events: 1, omitted: 0 });
    const superScope = await request(app).get("/cases/c1/timesketch-omitted?scope=super");
    expect(superScope.status).toBe(501);
  });
});
