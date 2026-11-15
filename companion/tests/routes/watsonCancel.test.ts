import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { AiCostStore } from "../../src/analysis/aiCost.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import { WATSON_CANCELLED_TEXT } from "../../src/analysis/ai/watson/round.js";
import { watsonRuns } from "../../src/analysis/ai/watson/runRegistry.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { PresidioApprovalRequired } from "../../src/analysis/presidio.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import {
  ProviderError,
  type AIProvider,
  type AnalyzeRequest,
  type AnalyzeResult,
} from "../../src/providers/provider.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// The Watson stop route, the running indicator on GET /watson, and the Idempotency-Key dedupe of
// POST /watson/message, on the real pipeline. watsonRuns is process-wide: every harness uses a
// fresh case id.

let caseCounter = 0;

const reply = (over: Record<string, unknown> = {}): string =>
  JSON.stringify({
    message: "I looked at the case.",
    workingOn: "initial access",
    learned: "",
    questionUpdates: [],
    newQuestions: [],
    request: null,
    search: null,
    memory: "memory v1",
    ...over,
  });

type Mode = "answer" | "block" | Error;

/** A provider that answers, blocks until released (rejecting when the send is stopped), or throws. */
class Gate implements AIProvider {
  readonly name = "fake";
  readonly model = "fake-model";
  readonly sent: AnalyzeRequest[] = [];
  mode: Mode = "answer";
  /** Steps used before `mode`, one per call: a raw reply text or an error to throw. */
  script: Array<string | Error> = [];
  private waiting: Array<() => void> = [];
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    const step = this.script.shift();
    if (step instanceof Error) throw step;
    if (step !== undefined) return { rawText: step, usage: { costUSD: 0.01 } };
    const mode = this.mode;
    if (mode instanceof Error) throw mode;
    if (mode === "block") await this.blocked(req.signal);
    return { rawText: reply(), usage: { costUSD: 0.01 } };
  }
  release(): void {
    const all = this.waiting;
    this.waiting = [];
    for (const go of all) go();
  }
  private blocked(signal: AbortSignal | undefined): Promise<void> {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) return reject(new ProviderError("Fake transport error: aborted", "transport"));
      signal?.addEventListener("abort", () =>
        reject(new ProviderError("Fake transport error: aborted", "transport")),
      );
      this.waiting.push(resolve);
    });
  }
}

/** A state store that runs a hook once on its next load (the round's preparation reads the state). */
class HookedState extends StateStore {
  onLoad: (() => Promise<void>) | undefined;
  override async load(caseId: string) {
    const hook = this.onLoad;
    this.onLoad = undefined;
    if (hook) await hook();
    return super.load(caseId);
  }
}

type Harness = Awaited<ReturnType<typeof harness>>;

async function harness(opts: { aiOn?: boolean; chatStore?: boolean } = {}) {
  const CASE = `cancel-c${++caseCounter}`;
  const root = await mkdtemp(join(tmpdir(), "dfir-watson-cancel-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new HookedState(store);
  await stateStore.save(emptyState(CASE));
  await new AiControlStore(store).save(CASE, { enabled: opts.aiOn ?? true, lastAnalyzedSeq: 0 });
  const aiCostStore = new AiCostStore(store);
  const stateLock = new StateLock();
  const provider = new Gate();
  const pipeline = new AnalysisPipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    stateLock,
    aiCostStore,
    anonStore: new AnonControlStore(store),
    retries: 0,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
  const broadcasts: string[] = [];
  const app = createApp(store, {
    stateStore,
    stateLock,
    pipeline,
    aiCostStore,
    activityLogStore: new ActivityLogStore(store),
    ...(opts.chatStore === false ? {} : { watsonChatStore: new WatsonChatStore(store) }),
    watsonProvider: () => provider,
    onWatson: () => broadcasts.push("watson_changed"),
  });
  const post = (key: string | undefined, text: string) => {
    const r = request(app).post(`/cases/${CASE}/watson/message`);
    return (key === undefined ? r : r.set("Idempotency-Key", key)).send({ text }).then((x) => x);
  };
  const aiSwitch = (enabled: boolean) => request(app).post(`/cases/${CASE}/ai-control`).send({ enabled });
  const cancel = () => request(app).post(`/cases/${CASE}/watson/cancel`).send({});
  const get = () => request(app).get(`/cases/${CASE}/watson`);
  return { app, CASE, provider, broadcasts, stateStore, post, aiSwitch, cancel, get };
}

async function until(check: () => boolean, ms = 3000): Promise<void> {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 5));
  }
}

type Turn = { role: string; text: string; error?: boolean };
const lastTurn = (body: { turns: Turn[] }): Turn => body.turns[body.turns.length - 1];

describe("Watson stop and running state", () => {
  it("GET /watson shows running while a message runs, and null after; every change pings watson_changed", async () => {
    const h = await harness();
    h.provider.mode = "block";
    const pending = h.post(undefined, "hi");
    await until(() => h.provider.sent.length === 1);
    expect((await h.get()).body.running).toMatchObject({ kind: "analyst", queued: 0 });
    h.provider.release();
    expect((await pending).status).toBe(200);
    expect((await h.get()).body.running).toBeNull();
    expect(h.broadcasts.filter((t) => t === "watson_changed").length).toBeGreaterThanOrEqual(3);
  });

  it("POST /cancel stops the running message: 200 { cancelled: 1 }, the message answers 200 with the stop note", async () => {
    const h = await harness();
    h.provider.mode = "block";
    const pending = h.post(undefined, "hi");
    await until(() => h.provider.sent.length === 1);
    const stop = await h.cancel();
    expect(stop.status).toBe(200);
    expect(stop.body).toEqual({ cancelled: 1 });
    const res = await pending;
    expect(res.status).toBe(200);
    expect(lastTurn(res.body).text).toBe(WATSON_CANCELLED_TEXT);
    expect((await h.get()).body.running).toBeNull();
  });

  it("POST /cancel with nothing running answers { cancelled: 0 }; AI off still lets it run", async () => {
    const h = await harness({ aiOn: false });
    const stop = await h.cancel();
    expect(stop.status).toBe(200);
    expect(stop.body).toEqual({ cancelled: 0 });
  });

  it("POST /cancel without a chat store is 501", async () => {
    const h = await harness({ chatStore: false });
    const stop = await h.cancel();
    expect(stop.status).toBe(501);
    expect(stop.body.error).toBe("Watson is not configured");
  });

  it("a bad key is refused before any work: no watson_changed broadcast", async () => {
    const h = await harness();
    expect((await h.post("short", "hi")).status).toBe(400);
    expect(h.broadcasts).toEqual([]);
  });

  it("POST /cancel on a missing case is 404", async () => {
    const h = await harness();
    expect((await request(h.app).post("/cases/no-such-case/watson/cancel").send({})).status).toBe(404);
  });

  it("GET /watson has running: null after a failed round", async () => {
    const h = await harness();
    h.provider.mode = new ProviderError("Fake auth", "auth");
    expect((await h.post(undefined, "hi")).status).toBe(200);
    expect((await h.get()).body.running).toBeNull();
  });
});

describe("Watson message dedupe (Idempotency-Key)", () => {
  it("a repeated Idempotency-Key returns the first chat and makes one provider call", async () => {
    const h = await harness();
    const k = "key-fake-0002"; // trufflehog:ignore
    const [a, b] = await Promise.all([h.post(k, "hi"), h.post(k, "hi")]);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect(b.body).toEqual(a.body);
    expect(h.provider.sent).toHaveLength(1);
    expect(lastTurn(a.body).role).toBe("watson");
  });

  it("a bad key is 400 and a reused key with other text is 409", async () => {
    const h = await harness();
    const bad = await h.post("short", "hi");
    expect(bad.status).toBe(400);
    expect(bad.body.error).toBe("The request key is not valid. Send the message again.");
    const k = "key-fake-0003"; // trufflehog:ignore
    expect((await h.post(k, "hi")).status).toBe(200);
    const other = await h.post(k, "other");
    expect(other.status).toBe(409);
    expect(other.body.error).toBe("This request key belongs to a different message. Send the message again.");
  });

  type Failure = { status: number; calls: number; arrange: (h: Harness) => void };
  // Each failure ends "failed" with a known first status and provider call count; AI goes back on
  // and the provider answers again before the resend.
  const failures: Record<string, Failure> = {
    aiOffDuringPrep: {
      status: 200, // the error turn is saved; the provider is never reached
      calls: 0,
      arrange: (h) => {
        h.stateStore.onLoad = async () => {
          await h.aiSwitch(false);
        };
      },
    },
    providerAuth: {
      status: 200,
      calls: 1,
      arrange: (h) => void (h.provider.script = [new ProviderError("Fake auth", "auth")]),
    },
    providerTransport: {
      status: 200,
      calls: 1,
      arrange: (h) => void (h.provider.script = [new ProviderError("Fake transport error", "transport")]),
    },
    presidioHoldOnFirstCall: {
      status: 409, // a hold before any reply: nothing was answered or paid
      calls: 1,
      arrange: (h) => void (h.provider.script = [new PresidioApprovalRequired([])]),
    },
  };

  it.each(Object.keys(failures))(
    "%s: a later resend with the same key runs a new round (Codex #7)",
    async (kind) => {
      const h = await harness();
      const f = failures[kind];
      f.arrange(h);
      const k = "key-fake-0004"; // trufflehog:ignore
      const first = await h.post(k, "hi");
      expect(first.status).toBe(f.status);
      expect(h.provider.sent).toHaveLength(f.calls);
      await h.aiSwitch(true);
      const again = await h.post(k, "hi");
      expect(again.status).toBe(200);
      expect(h.provider.sent).toHaveLength(f.calls + 1);
      expect(lastTurn(again.body).role).toBe("watson");
    },
  );

  it("a Presidio hold on the second hop, after the first reply was saved, replays: no second paid round", async () => {
    const h = await harness();
    h.provider.script = [
      reply({ lookup: { source: "forensic", text: "rclone" } }),
      new PresidioApprovalRequired([]),
    ];
    const k = "key-fake-0008"; // trufflehog:ignore
    const first = await h.post(k, "hi");
    expect(first.status).toBe(409);
    expect(h.provider.sent).toHaveLength(2);
    const again = await h.post(k, "hi");
    expect(again.status).toBe(200);
    expect(h.provider.sent).toHaveLength(2); // no new round, so no new promotion either
    const turns = again.body.turns as Turn[];
    expect(turns.filter((t) => t.role === "analyst")).toHaveLength(1);
    expect(lastTurn(again.body).role).toBe("watson");
  });

  it("concurrent waiters on a failed first round get the same answer", async () => {
    const h = await harness();
    h.provider.mode = new ProviderError("Fake auth", "auth");
    const k = "key-fake-0005"; // trufflehog:ignore
    const [a, b] = await Promise.all([h.post(k, "hi"), h.post(k, "hi")]);
    expect(b.status).toBe(a.status);
    expect(b.body).toEqual(a.body);
    expect(h.provider.sent).toHaveLength(1);
  });

  it("a replay after AI is switched off still returns the first chat (Codex #8)", async () => {
    const h = await harness();
    const k = "key-fake-0006"; // trufflehog:ignore
    const a = await h.post(k, "hi");
    expect(a.status).toBe(200);
    await h.aiSwitch(false);
    const b = await h.post(k, "hi");
    expect(b.status).toBe(200);
    expect(lastTurn(b.body)).toEqual(lastTurn(a.body));
    expect(h.provider.sent).toHaveLength(1);
  });

  it("a replay makes no model call, so it does not spend the case's AI budget (20 a minute)", async () => {
    const h = await harness();
    const k = "key-fake-0009"; // trufflehog:ignore
    expect((await h.post(k, "hi")).status).toBe(200);
    for (let i = 0; i < 25; i++) expect((await h.post(k, "hi")).status).toBe(200);
    expect(h.provider.sent).toHaveLength(1);
  });

  it("a cancelled round replays: the resend gets the stop note and no new provider call", async () => {
    const h = await harness();
    h.provider.mode = "block";
    const k = "key-fake-0007"; // trufflehog:ignore
    const pending = h.post(k, "hi");
    await until(() => h.provider.sent.length === 1);
    await h.cancel();
    expect(lastTurn((await pending).body).text).toBe(WATSON_CANCELLED_TEXT);
    h.provider.mode = "answer";
    const again = await h.post(k, "hi");
    expect(again.status).toBe(200);
    expect(lastTurn(again.body).text).toBe(WATSON_CANCELLED_TEXT);
    expect(h.provider.sent).toHaveLength(1);
  });

  it("four new messages sent in the same tick: exactly one is 429 (the admission counts checks in flight)", async () => {
    const h = await harness();
    h.provider.mode = "block";
    const keys = ["key-fake-0201", "key-fake-0202", "key-fake-0203", "key-fake-0204"]; // trufflehog:ignore
    const pending = keys.map((k, i) => h.post(k, `same tick ${i}`));
    await until(() => h.provider.sent.length === 1 && watsonRuns.status(h.CASE)?.queued === 2);
    expect((await h.cancel()).body).toEqual({ cancelled: 3 });
    const statuses = (await Promise.all(pending)).map((r) => r.status);
    expect(statuses.filter((s) => s === 429)).toHaveLength(1);
    expect(statuses.filter((s) => s === 200)).toHaveLength(3);
  });

  it("a fourth concurrent message is 429; a duplicate at capacity attaches; capacity frees after a cancel (Codex #9)", async () => {
    const h = await harness();
    h.provider.mode = "block";
    const keys = ["key-fake-0101", "key-fake-0102", "key-fake-0103"]; // trufflehog:ignore
    const pending = keys.map((k, i) => h.post(k, `message ${i}`));
    await until(() => h.provider.sent.length === 1 && watsonRuns.status(h.CASE)?.queued === 2);
    const fourth = await h.post("key-fake-0104", "message 4"); // trufflehog:ignore
    expect(fourth.status).toBe(429);
    expect(fourth.body.error).toBe(
      "Watson already has 3 messages for this case. Wait for an answer, then send again.",
    );
    const noKey = await h.post(undefined, "message 5");
    expect(noKey.status).toBe(429);
    const duplicate = h.post(keys[0], "message 0");
    expect((await h.cancel()).body).toEqual({ cancelled: 3 });
    const done = await Promise.all([...pending, duplicate]);
    expect(done.map((r) => r.status)).toEqual([200, 200, 200, 200]);
    h.provider.mode = "answer";
    expect((await h.post("key-fake-0105", "message 6")).status).toBe(200); // trufflehog:ignore
  });
});
