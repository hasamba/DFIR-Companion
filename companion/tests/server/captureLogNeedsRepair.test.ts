import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import sharp from "sharp";
import type { Response } from "express";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, type AiStatusEvent } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CommentsStore } from "../../src/analysis/comments.js";
import { _resetDedupCache } from "../../src/ingest/captureIngest.js";
import { AuditLogNeedsRepairError } from "../../src/storage/auditLogNeedsRepairError.js";
import { sendPipelineError } from "../../src/routes/presidioApproval.js";

// #2252: one corrupted line in captures.jsonl blocks every later capture for the case. That stays
// fail-closed, but the refusal must say what to fix: a 409 with a code the extension keeps queued
// on, a message naming the case and the line, and an ai_status the dashboard shows without it.

let store: CaseStore;
let statuses: { caseId: string; event: AiStatusEvent }[];
let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  _resetDedupCache();
  statuses = [];
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-log-repair-route-")));
  app = createApp(store, {
    stateStore: new StateStore(store),
    commentsStore: new CommentsStore(store),
    onAiStatus: (caseId, event) => statuses.push({ caseId, event }),
  });
  await store.createCase({ caseId: "c1", name: "Case", investigator: "alice", aiProvider: null });
});

async function png(): Promise<string> {
  const bytes = await sharp({ create: { width: 24, height: 24, channels: 3, background: "#3366aa" } })
    .png()
    .toBuffer();
  return bytes.toString("base64");
}

const capture = async () => ({
  caseId: "c1",
  timestamp: "2026-10-29T10:00:00.000Z",
  url: "https://velociraptor.local/hunts",
  tabTitle: "Hunts",
  triggerType: "manual",
  imageBase64: await png(),
});

describe("POST /captures with a corrupted capture log (#2252)", () => {
  it("answers 409 capture-log-needs-repair naming the case and the bad line", async () => {
    const corrupted = `${JSON.stringify({ caseId: "c1", sequenceNumber: 1 })}\n{"caseId":"c1","seq\n`;
    await writeFile(store.capturesLogPath("c1"), corrupted, "utf8");

    const res = await request(app)
      .post("/captures")
      .send(await capture());

    expect(res.status).toBe(409);
    expect(res.body.code).toBe("capture-log-needs-repair");
    expect(res.body.error).toContain('Case "c1"');
    expect(res.body.error).toContain("line 2");
    expect(res.body.error).not.toContain(store.casesRoot);
    // Fail closed: nothing written past the bad line, no screenshot saved under a guessed number.
    expect(await readFile(store.capturesLogPath("c1"), "utf8")).toBe(corrupted);
    expect(await readdir(join(store.caseDir("c1"), "screenshots"))).toEqual([]);
  });

  it("tells the dashboard through the case's AI status line", async () => {
    await writeFile(store.capturesLogPath("c1"), "{broken\n", "utf8");
    await request(app)
      .post("/captures")
      .send(await capture());

    const repair = statuses.filter((s) => s.caseId === "c1" && s.event.status === "error");
    expect(repair).toHaveLength(1);
    expect(repair[0].event.detail).toMatch(/capture log/);
    expect(repair[0].event.detail).toContain("line 1");
  });

  it("captures normally again once the line is repaired", async () => {
    await writeFile(store.capturesLogPath("c1"), "{broken\n", "utf8");
    expect(
      (
        await request(app)
          .post("/captures")
          .send(await capture())
      ).status,
    ).toBe(409);
    await writeFile(store.capturesLogPath("c1"), "", "utf8");
    const res = await request(app)
      .post("/captures")
      .send(await capture());
    expect(res.status).toBe(201);
    expect(res.body.sequenceNumber).toBe(1);
  });
});

describe("sendPipelineError with a corrupted import log (#2252)", () => {
  it("answers 409 with the log's own code instead of a bare 500", () => {
    let status = 0;
    let body: unknown;
    const res = {
      status(code: number) {
        status = code;
        return this;
      },
      json(b: unknown) {
        body = b;
        return this;
      },
    } as unknown as Response;
    sendPipelineError(res, new AuditLogNeedsRepairError("c1", "import", "imports.jsonl", 4, "bad JSON"));
    expect(status).toBe(409);
    expect(body).toMatchObject({ code: "import-log-needs-repair" });
    expect((body as { error: string }).error).toContain("line 4");
  });
});
