// #3008 — the SO-CRATES job runner sends one message per submission, with the counts its ingest
// returned, and startup recovery reports a submission a restart interrupted. Synthetic data only.
import { describe, expect, it, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("../../src/integrations/socrates/socratesApi.js", () => ({
  checkStatus: vi.fn(async (_base: string, md5: string) =>
    md5.startsWith("bad") ? { status: "error", message: "analysis failed upstream" } : { status: "ready" },
  ),
  fetchVerdicts: vi.fn(async () => ({ text: "{}" })),
}));

import { CaseStore } from "../../src/storage/caseStore.js";
import type { NotificationEvent } from "../../src/analysis/notifications.js";
import type { SocratesJob } from "../../src/integrations/socrates/socratesJobStore.js";
import type { ToolConfig } from "../../src/integrations/tools/toolConfig.js";
import { createSocratesJobRunner } from "../../src/composition/socratesJobRunner.js";
import { pollFor } from "../helpers/poll.js";

const cfg = { baseUrl: "http://socrates.invalid", timeoutMs: 60_000 } as ToolConfig & { baseUrl: string };

async function harness(counts?: { added: number; highCritical: number }) {
  const root = await mkdtemp(join(tmpdir(), "dfir-socrates-notify-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const sent: NotificationEvent[] = [];
  const runner = createSocratesJobRunner({
    store,
    ingestStreamed: async () => ({ addedEvents: 1, addedIocs: 0, ...(counts ? { counts } : {}) }),
    socratesConfig: () => cfg,
    dispatchNotify: (e) => void sent.push(e),
  });
  return { runner, sent };
}

const job = (jobId: string, md5: string, over: Partial<SocratesJob> = {}): SocratesJob => ({
  jobId,
  md5,
  sourceName: "sample.zip",
  status: "processing",
  startedAt: new Date().toISOString(),
  submissionId: "sub-1",
  ...over,
});

async function launchAll(h: Awaited<ReturnType<typeof harness>>, jobs: SocratesJob[]): Promise<void> {
  h.runner.openSubmission("c1", "sub-1", "sample.zip");
  for (const j of jobs) {
    h.runner.reserve(j.jobId);
    await h.runner.jobs.upsert("c1", j);
    h.runner.launch("c1", j, cfg);
  }
  h.runner.sealSubmission("c1", "sub-1");
}

describe("SO-CRATES job runner messages (#3008)", () => {
  it("a single file sends one Import finished message with its ingest counts", async () => {
    const h = await harness({ added: 7, highCritical: 2 });
    await launchAll(h, [job("j1", "good1", { sourceName: "one.pcap" })]);
    await pollFor("the import message", async () => h.sent[0]);
    expect(h.sent).toHaveLength(1);
    expect(h.sent[0].kind).toBe("import");
    expect(h.sent[0].lines).toContain("Forensic timeline: +7 events (2 High/Critical)");
  });

  it("an archive with a failed entry sends one message for the submission", async () => {
    const h = await harness({ added: 1, highCritical: 0 });
    await launchAll(h, [
      job("j1", "good1", { zipEntry: "sample.zip!a" }),
      job("j2", "bad2", { zipEntry: "sample.zip!b" }),
      job("j3", "good3", { zipEntry: "sample.zip!c" }),
    ]);
    await pollFor("the import message", async () => h.sent[0]);
    await new Promise((r) => setTimeout(r, 50));
    expect(h.sent).toHaveLength(1);
    expect(h.sent[0].title).toBe("Import finished, 1 failed: SO-CRATES: sample.zip");
    expect(h.sent[0].lines).toContain("Files: 3");
    expect(h.sent[0].lines).toContain("Forensic timeline: +2 events (0 High/Critical)");
  });

  it("an ingest that cannot count says the counts are not available", async () => {
    const h = await harness(undefined);
    await launchAll(h, [job("j1", "good1")]);
    await pollFor("the import message", async () => h.sent[0]);
    expect(h.sent[0].lines).toContain("Event counts are not available for this import");
  });

  it("startup recovery sends one Import failed message for an interrupted submission", async () => {
    const h = await harness();
    await h.runner.jobs.upsert("c1", job("j1", "good1", { status: "importing" }));
    await h.runner.jobs.upsert("c1", job("j2", "good2", { status: "importing" }));
    await h.runner.resumeAll();
    expect(h.sent).toHaveLength(1);
    expect(h.sent[0].title).toBe("Import failed: SO-CRATES: sample.zip");
    // A second recovery finds nothing unfinished: no second message.
    await h.runner.resumeAll();
    expect(h.sent).toHaveLength(1);
  });

  it("a job whose recovery throws still settles its submission as failed (#3035)", async () => {
    const h = await harness();
    await h.runner.jobs.upsert("c1", job("j1", "good1", { status: "importing", zipEntry: "sample.zip!a" }));
    await h.runner.jobs.upsert("c1", job("j2", "good2", { status: "importing", zipEntry: "sample.zip!b" }));
    // Writing j1's interrupted state fails: recovery logs it and moves on to j2.
    const real = h.runner.jobs.upsert.bind(h.runner.jobs);
    vi.spyOn(h.runner.jobs, "upsert").mockImplementation(async (caseId, j) => {
      if (j.jobId === "j1") throw new Error("disk full");
      return real(caseId, j);
    });
    await h.runner.resumeAll();
    expect(h.sent).toHaveLength(1);
    expect(h.sent[0].title).toBe("Import failed: SO-CRATES: sample.zip");
    const text = h.sent[0].lines.join("\n");
    expect(text).toContain("sample.zip!a");
    expect(text).toContain("sample.zip!b");
  });

  it("a case whose recovery throws outright still reports its adopted submission (#3035)", async () => {
    const h = await harness();
    await h.runner.jobs.upsert("c1", job("j1", "good1", { status: "importing" }));
    // The first list (adoption) works; recovery's own list then fails.
    const real = h.runner.jobs.list.bind(h.runner.jobs);
    vi.spyOn(h.runner.jobs, "list")
      .mockImplementationOnce(real)
      .mockRejectedValueOnce(new Error("read failed"));
    await h.runner.resumeAll();
    expect(h.sent).toHaveLength(1);
    expect(h.sent[0].title).toBe("Import failed: SO-CRATES: sample.zip");
  });
});
