import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { createApp } from "../../src/server.js";
import { readZip } from "../../src/analysis/zipArchive.js";
import { backfillHighSeverityFindings } from "../../src/analysis/highSeverityFindings.js";
import type { OcrRunner } from "../../src/analysis/ocrRedact.js";

const noOcr: OcrRunner = { recognize: async () => [] };

// The auto-finding title is a shortened copy of the event description. The email below starts
// before the title's length cap and ends after it, so a cut at a fixed character count would leave
// the start of the user name behind as a fragment no detector recognises.
const USER = "zorbaqvexmul";
const DESCRIPTION =
  "Inbox forwarding rule created on the mailbox server that forwards all mail to " +
  `${USER}@example.org outside the org`;

describe("redacted export — shortened auto-finding title", () => {
  it("keeps no part of a user name the title cap fell inside", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-redact-titlecut-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    const base = {
      ...emptyState("c1"),
      forensicTimeline: [
        {
          id: "e1",
          timestamp: "2026-01-01T00:00:00Z",
          description: DESCRIPTION,
          severity: "High" as const,
          mitreTechniques: [],
          relatedFindingIds: [],
          sourceScreenshots: [],
        },
      ],
    };
    const state = backfillHighSeverityFindings(base, new Set(["e1"]), "2026-01-01T00:00:00Z");
    expect(state.findings).toHaveLength(1);
    await stateStore.save(state);

    const app = createApp(cases, {
      stateStore,
      reportWriter: new ReportWriter(cases, stateStore),
      ocrRunner: noOcr,
    });
    const res = await request(app)
      .get("/cases/c1/export/redacted?screenshots=0")
      .buffer()
      .parse((r, cb) => {
        const chunks: Buffer[] = [];
        r.on("data", (c: Buffer) => chunks.push(c));
        r.on("end", () => cb(null, Buffer.concat(chunks)));
      });
    expect(res.status).toBe(200);

    const entries = readZip(res.body as Buffer);
    expect(entries.length).toBeGreaterThan(0);
    // Any 5-character run of the user name is a leak.
    const fragments = Array.from({ length: USER.length - 4 }, (_, i) => USER.slice(i, i + 5));
    for (const e of entries) {
      const text = e.data.toString("utf8").toLowerCase();
      for (const frag of fragments) expect(text, `${e.path} holds "${frag}"`).not.toContain(frag);
    }
  });
});
