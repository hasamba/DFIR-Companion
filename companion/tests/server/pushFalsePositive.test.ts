import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { FalsePositiveStore, markerId } from "../../src/analysis/falsePositive.js";
import { IrisExportStore } from "../../src/integrations/iris/irisExportStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { IrisClient } from "../../src/integrations/iris/irisClient.js";
import type {
  MispPushClientLike,
  MispEventCreate,
  MispAttrBody,
} from "../../src/integrations/misp/mispPushClient.js";

// #951: an event the analyst marked false positive is hidden from every report, from synthesis
// and from the deep pass — but the MISP and DFIR-IRIS pushes read the raw state and sent it
// anyway. Neither integration retracts a timeline row once pushed, so the mistake was permanent
// on the remote side. Both pushes now read the same projection the reports read
// (reports/filteredState.ts), exactly as the Timesketch and Notion pushes already did.

function ev(id: string, description: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-01-01T00:00:00Z",
    description,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

function mockIris() {
  const events: { event_title: string }[] = [];
  const client = {
    async ping() {},
    async findCaseByName() {
      return null;
    },
    async createCase(body: { case_name: string }) {
      return { caseId: 100, caseName: body.case_name };
    },
    async setSummary() {},
    async iocTypeMap() {
      return new Map<string, number>();
    },
    async assetTypeMap() {
      return new Map<string, number>();
    },
    async eventCategoryMap() {
      return new Map<string, number>();
    },
    async taskStatusMap() {
      return new Map<string, number>([["to do", 1]]);
    },
    async listAssets() {
      return [];
    },
    async addAsset() {
      return 1;
    },
    async listIocs() {
      return [];
    },
    async addIoc() {
      return 1;
    },
    async listEvents() {
      return [];
    },
    async addEvent(_cid: number, body: { event_title: string }) {
      events.push(body);
      return events.length;
    },
    async listTasks() {
      return [];
    },
    async addTask() {
      return 1;
    },
    async listDirectories() {
      return [];
    },
    async addDirectory() {
      return 1;
    },
    async deleteDirectory() {},
    async addNote() {
      return 1;
    },
  };
  return { client: client as unknown as IrisClient, events };
}

function mockMisp() {
  const attributes: MispAttrBody[] = [];
  const client: MispPushClientLike = {
    async ping() {},
    async findEventByTag() {
      return null;
    },
    async createEvent(_body: MispEventCreate) {
      return "7";
    },
    async addTagToEvent() {},
    async listAttributes() {
      return [];
    },
    async addAttribute(_eventId: string, body: MispAttrBody) {
      attributes.push(body);
    },
  };
  return { client, attributes };
}

describe("push routes honour false-positive markers (#951)", () => {
  let store: CaseStore;
  let stateStore: StateStore;
  let reportWriter: ReportWriter;

  beforeEach(async () => {
    store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-push-fp-")));
    stateStore = new StateStore(store);
    const falsePositives = new FalsePositiveStore(store);
    reportWriter = new ReportWriter(store, stateStore, { falsePositives });
    await store.createCase({ caseId: "c1", name: "c1", investigator: "tester", aiProvider: null });
    const state = emptyState("c1");
    state.forensicTimeline.push(
      ev("e-real", "PsExec lateral movement"),
      ev("e-fp", "Backup agent scheduled task"),
    );
    await stateStore.save(state);
    await falsePositives.save("c1", [
      {
        id: markerId("event", "e-fp"),
        kind: "event",
        ref: "e-fp",
        reason: "known-good-tool",
        note: "",
        markedAt: "2026-01-02T00:00:00Z",
        markedBy: "tester",
      },
    ]);
  });

  it("DFIR-IRIS push never sends an event marked false positive", async () => {
    const { client, events } = mockIris();
    const app = createApp(store, {
      stateStore,
      reportWriter,
      irisClient: client,
      irisExportStore: new IrisExportStore(store),
    });
    const res = await request(app).post("/cases/c1/push/iris").send({});
    expect(res.status).toBe(200);
    expect(events.map((e) => e.event_title)).toEqual(["PsExec lateral movement"]);
  });

  it("MISP push never sends an event marked false positive", async () => {
    const { client, attributes } = mockMisp();
    const app = createApp(store, { stateStore, reportWriter, mispPushClient: client });
    const res = await request(app).post("/cases/c1/push/misp").send({});
    expect(res.status).toBe(200);
    const timeline = attributes.filter((a) => a.category === "Internal reference").map((a) => a.value);
    expect(timeline).toEqual(["[2026-01-01T00:00:00Z] PsExec lateral movement"]);
  });
});
