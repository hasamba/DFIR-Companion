// A Jev stand-in and a case for the Jev routes' job tests (#2425): the missed-evidence review and
// the containment check now run as jobs, so their tests need a Jev that answers (or refuses), a
// Presidio client that can hold, and a JobManager on the app.
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { emptyState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { PresidioClient } from "../../src/analysis/presidio.js";
import type { AIProvider, AnalyzeResult } from "../../src/providers/provider.js";
import type { JobManager } from "../../src/analysis/jobManager.js";

export const JEV_JOB_ENV = [
  "DFIR_JEV_ENABLED",
  "DFIR_JEV_KEY",
  "DFIR_JEV_PROVIDER",
  "DFIR_JEV_BASE_URL",
  "DFIR_JEV_MODEL",
  "DFIR_JEV_GRADING",
  "DFIR_ANONYMIZE",
] as const;

export const JEV_TEST_MODEL = "jev-job-test-model";
const PERSON = "Rob Roe";

/** "answer" grades everything; "refuse" answers 401, which the client does not retry. */
export type JevMode = "answer" | "refuse";

/** Start a Jev stand-in and point the env at it. Returns a close function. */
export async function startJevStub(mode: () => JevMode): Promise<{ close: () => Promise<void> }> {
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (mode() === "refuse") {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { message: "no credentials" } }));
        return;
      }
      const questions = JSON.parse(body).questions as Record<string, { type: string; criteria?: object }>;
      const answers: Record<string, unknown> = {};
      for (const [id, q] of Object.entries(questions))
        answers[id] =
          q.type === "noul"
            ? { type: "noul", noul: 0 }
            : q.type === "choice"
              ? {
                  type: "choice",
                  choice: Object.keys(q.criteria ?? {})[0],
                  probabilities: {},
                  confidence: 0.9,
                }
              : { type: "score", score: 1, legend: {}, probabilities: {}, confidence: 0.5 };
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ model: "jev-stub", answers, usage: { input_tokens: 1, output_tokens: 1 } }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  process.env.DFIR_JEV_ENABLED = "1";
  process.env.DFIR_JEV_KEY = "jev-test-credential-NOTAREALKEY";
  process.env.DFIR_JEV_MODEL = JEV_TEST_MODEL;
  process.env.DFIR_JEV_BASE_URL = `http://127.0.0.1:${(server.address() as AddressInfo).port}/decisions`;
  return { close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

const row = (id: string, severity: ForensicEvent["severity"], description: string): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description,
  severity,
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

export const JOB_TEST_FINDING: Finding = {
  id: "f1",
  severity: "High",
  title: "Credential theft",
  description: "mimikatz ran",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: ["T1003"],
  relatedEventIds: ["e1"],
  firstSeen: "2026-01-01T00:00:00Z",
  lastUpdated: "2026-01-01T00:00:00Z",
  status: "open",
};

class NoProvider implements AIProvider {
  readonly name = "none";
  readonly model = "none";
  async analyze(): Promise<AnalyzeResult> {
    throw new Error("the chat provider must not be called");
  }
}

export interface JevJobCaseOptions {
  jobManager: JobManager;
  /** Every super-timeline row is also in the forensic timeline, so the review grades nothing. */
  allAnalyzed?: boolean;
  /** Presidio flags a name in the payload, so the call holds for approval. */
  presidioFlags?: boolean;
}

/** A case with one finding, one forensic event and one archive row, on an app with a JobManager. */
export async function jevJobCase(opts: JevJobCaseOptions) {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-jev-job-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const archive = row("r1", "Info", `logon by ${PERSON}`);
  await stateStore.save({
    ...emptyState("c1"),
    findings: [JOB_TEST_FINDING],
    forensicTimeline: [
      row("e1", "High", `mimikatz run by ${PERSON}`),
      ...(opts.allAnalyzed ? [archive] : []),
    ],
  });
  const superTimelineStore = new SuperTimelineStore(cases);
  await superTimelineStore.append("c1", [archive]);
  const client: PresidioClient = {
    analyze: async (text) =>
      opts.presidioFlags && text.includes(PERSON)
        ? [{ entityType: "PERSON", value: PERSON, score: 0.95 }]
        : [],
  };
  const pipeline = buildRuntimePipeline({
    provider: new NoProvider(),
    stateStore,
    store: cases,
    imageLoader: async () => ({ base64: "AA", mimeType: "image/webp" }),
    presidio: { client, url: "http://localhost:5002", minScore: 0.6 },
  });
  const app = createApp(cases, { pipeline, stateStore, superTimelineStore, jobManager: opts.jobManager });
  return { app, stateStore };
}
