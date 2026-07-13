import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { patternKey } from "../../src/analysis/prevalence.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #15b: marking an EVENT false positive stamps the anchor's prevalence pattern key onto the marker, so a
// later import can recognize the same pattern re-arriving and suggest a bulk-mark.

function ev(partial: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return { timestamp: "2026-05-20T09:00:00Z", description: "", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...partial };
}

describe("POST /cases/:id/false-positive stamps patternFingerprint (#15b)", () => {
  it("captures the anchor event's pattern key on the event marker (and not on IOC markers)", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-fpprop-")));
    const stateStore = new StateStore(store);
    const app = createApp(store, { stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    const anchor = ev({ id: "e1", processName: "robocopy.exe", description: "robocopy C:\\data\\1 \\\\srv\\bak /mir" });
    const state = emptyState("c1");
    state.forensicTimeline.push(anchor);
    await stateStore.save(state);

    await request(app).post("/cases/c1/false-positive").send({ kind: "event", ref: "e1", reason: "duplicate" });
    await request(app).post("/cases/c1/false-positive").send({ kind: "ioc", ref: "1.2.3.4", reason: "duplicate" });

    const res = await request(app).get("/cases/c1/false-positive");
    const eventMarker = res.body.find((m: { kind: string }) => m.kind === "event");
    const iocMarker = res.body.find((m: { kind: string }) => m.kind === "ioc");
    expect(eventMarker.patternFingerprint).toBe(patternKey(anchor));
    expect(eventMarker.patternFingerprint).toMatch(/^proc:robocopy\.exe\|/);
    expect(iocMarker.patternFingerprint).toBeUndefined();   // only event markers carry a fingerprint
  });
});
