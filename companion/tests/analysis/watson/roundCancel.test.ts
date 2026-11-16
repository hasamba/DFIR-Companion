import { describe, expect, it } from "vitest";
import { WATSON_CANCELLED_TEXT, runWatsonRound } from "../../../src/analysis/ai/watson/round.js";
import {
  WatsonCancelled,
  WatsonRoundTimedOut,
  watsonRoundMaxMs,
  type WatsonRoundContext,
} from "../../../src/analysis/ai/watson/roundContext.js";
import { WatsonRunRegistry } from "../../../src/analysis/ai/watson/runRegistry.js";
import { ProviderError } from "../../../src/providers/provider.js";
import type { ConverseRequest, ConverseResult } from "../../../src/providers/toolCalling.js";
import {
  CASE,
  Scripted,
  calls,
  final,
  forensic,
  lastTurn,
  reply,
  toolHarness,
} from "./roundToolsFixtures.js";
import { answer, harness, log, superLookup, writes, type HarnessOpts } from "./superPromoteFixtures.js";

// Task 5: an analyst's Stop on a running round. The stop is checked before every send and tool, at
// the provider fetch (an abort is not retried as a transport error), and at each commit-phase step.

/** A step that fails the way anthropic.ts post() wraps a fetch abort, when the request was stopped. */
const abortAware =
  (next: ConverseResult) =>
  (req: ConverseRequest): ConverseResult | Error =>
    req.signal?.aborted ? new ProviderError("Scripted transport error: aborted", "transport") : next;

function deferred() {
  let release!: () => void;
  const until = new Promise<void>((r) => (release = r));
  return { until, release };
}

const q = { question: "Did rclone run on WS-FAKE01?", why: "it copies files" };

describe("a stop in tool mode", () => {
  it("a stop during the second send keeps the first lookup and its cost, writes the stop note, and does not retry", async () => {
    const reg = new WatsonRunRegistry();
    const p = new Scripted([calls(forensic({ text: "a" })), abortAware(final())], {
      tokens: 10,
      onSend: (n) => {
        if (n === 2) reg.cancel(CASE);
      },
    });
    const warns: string[] = [];
    const spy = { ...log, warn: (line: string) => void warns.push(line) };
    const h = await toolHarness(p, { retries: 3, ctx: { runs: reg, log: spy } });
    const chat = await h.run();
    expect(p.sent).toHaveLength(2);
    // Review Focus 3: not retried as a transport error, and not logged as one.
    expect(warns.filter((w) => /retrying|transport error/.test(w))).toEqual([]);
    expect(lastTurn(chat)).toMatchObject({ role: "system", error: true, text: WATSON_CANCELLED_TEXT });
    expect(lastTurn(chat).lookups).toHaveLength(1);
    expect(chat.tokens).toBe(10);
    expect(chat.proposals.filter((x) => x.turnId === lastTurn(chat).id)).toEqual([]);
  });

  it("a stop after a send that asked for tools runs no tool and no second send", async () => {
    const reg = new WatsonRunRegistry();
    const p = new Scripted([calls(forensic({ text: "a" }), forensic({ text: "b" })), final()], {
      onSend: (n) => {
        if (n === 1) reg.cancel(CASE);
      },
    });
    const h = await toolHarness(p, { ctx: { runs: reg } });
    const chat = await h.run();
    expect(p.sent).toHaveLength(1);
    expect(lastTurn(chat).text).toBe(WATSON_CANCELLED_TEXT);
    expect(lastTurn(chat).lookups).toBeUndefined();
  });

  it("a stop after the final reply drops the reply and its proposals", async () => {
    const reg = new WatsonRunRegistry();
    const p = new Scripted([final(reply({ newQuestions: [q] }))], {
      onSend: () => void reg.cancel(CASE),
    });
    const h = await toolHarness(p, { ctx: { runs: reg } });
    const chat = await h.run();
    expect(lastTurn(chat)).toMatchObject({ role: "system", error: true, text: WATSON_CANCELLED_TEXT });
    expect(chat.proposals.filter((x) => x.status === "pending")).toEqual([]);
    expect(chat.turns.some((t) => t.role === "watson")).toBe(false);
  });

  it("a stop that lands during the continuation read stops the tool (Codex #5)", async () => {
    const reg = new WatsonRunRegistry();
    let armed = false;
    const p = new Scripted([calls(forensic({ text: "a" })), final()], {
      onSend: () => void (armed = true),
    });
    const canContinue = async () => {
      if (armed) reg.cancel(CASE); // the stop lands while the read is pending
      return null;
    };
    const h = await toolHarness(p, { ctx: { runs: reg, canContinue } });
    const chat = await h.run();
    expect(p.sent).toHaveLength(1);
    expect(lastTurn(chat).text).toBe(WATSON_CANCELLED_TEXT);
    expect(lastTurn(chat).lookups).toBeUndefined();
  });

  it("onRunChange fires at the start and at the end, also when the round fails", async () => {
    const pings: string[] = [];
    const reg = new WatsonRunRegistry();
    const ctx = { runs: reg, onRunChange: (id: string) => void pings.push(id) };
    const ok = await toolHarness(new Scripted([final()]), { ctx });
    await ok.run();
    expect(pings).toEqual([CASE, CASE]);
    expect(reg.status(CASE)).toBeNull();
    const bad = await toolHarness(new Scripted([new ProviderError("HTTP 500 boom", "transport")]), { ctx });
    const chat = await bad.run();
    expect(lastTurn(chat).error).toBe(true);
    expect(pings).toEqual([CASE, CASE, CASE, CASE]);
    expect(reg.status(CASE)).toBeNull();
  });
});

/** The one-step harness with a run registry on its context. */
async function oneStep(replies: string[], o: HarnessOpts = {}, over: Partial<WatsonRoundContext> = {}) {
  const reg = over.runs ?? new WatsonRunRegistry();
  const h = await harness(replies, o);
  const ctx: WatsonRoundContext = { ...h.ctx, runs: reg, ...over };
  const run = (text = "any rclone?", extra: Partial<Parameters<typeof runWatsonRound>[2]> = {}) =>
    runWatsonRound(ctx, CASE, { text, source: "dashboard", ...extra });
  const inTimeline = async (id: string) =>
    (await h.stateStore.load(CASE)).forensicTimeline.some((e) => e.id === id);
  return { ...h, reg, ctx, run, inTimeline };
}

describe("a stop in one-step mode", () => {
  it("a queued round that was stopped never calls the provider and keeps the analyst's words", async () => {
    const gate = deferred();
    const started = deferred();
    const h = await oneStep([], {
      onCall: async (n) => {
        if (n !== 1) return;
        started.release();
        await gate.until;
      },
    });
    const a = h.run("first question");
    await started.until;
    const b = h.run("second question");
    expect(h.reg.status(CASE)).toMatchObject({ kind: "analyst", queued: 1 });
    expect(h.reg.cancel(CASE)).toBe(2);
    gate.release();
    const [chatA, chatB] = await Promise.all([a, b]);
    expect(h.provider.calls).toBe(1);
    expect(lastTurn(chatA).text).toBe(WATSON_CANCELLED_TEXT);
    expect(lastTurn(chatB).text).toBe(WATSON_CANCELLED_TEXT);
    expect(chatB.turns.some((t) => t.role === "analyst" && t.text === "second question")).toBe(true);
    // The registry is empty after the last queued, stopped round settles.
    expect(h.reg.status(CASE)).toBeNull();
  });

  it("a promotion that started before the stop stays; Auto applies nothing after the stop", async () => {
    const reg = new WatsonRunRegistry();
    const second = reply({ ...answer(["raw1"]), newQuestions: [q] });
    const h = await oneStep(
      [reply(superLookup()), second],
      {
        mode: "auto",
        promote: (real) => async (caseId, events, o) => {
          reg.cancel(caseId);
          return real(caseId, events, o);
        },
      },
      { runs: reg },
    );
    const chat = await h.run();
    expect(await h.inTimeline("raw1")).toBe(true);
    const asked = chat.proposals.find((p) => p.kind === "question_new");
    expect(asked?.status).toBe("pending");
    expect(chat.turns.some((t) => t.role === "watson")).toBe(true);
  });

  it("without a stop the same round's question is applied by Auto (control)", async () => {
    const second = reply({ ...answer(["raw1"]), newQuestions: [q] });
    const h = await oneStep([reply(superLookup()), second], { mode: "auto" });
    const chat = await h.run();
    expect(chat.proposals.find((p) => p.kind === "question_new")?.status).toBe("applied");
  });

  const cited = reply({
    ...answer(["raw1"]),
    newQuestions: [q],
    ...writes({ report: [{ field: "conclusions", text: "Data left via rclone (raw1)." }] }),
  });

  it.each(["writeInputs", "planRefs", "writable"] as const)(
    "a stop while %s is pending: no promotion and no new proposal (Codex #3)",
    async (stage) => {
      let stop = () => 0;
      let armed = false;
      const h = await oneStep([reply(superLookup()), cited], {
        onCall: (n) => void (armed = n === 2),
      });
      stop = () => h.reg.cancel(CASE);
      const ctx = h.ctx;
      if (stage === "writeInputs") {
        const load = ctx.reportText!.load;
        ctx.reportText = { ...ctx.reportText!, load: async (c) => (stop(), load(c)) };
      } else if (stage === "planRefs") {
        const has = h.stateStore.hasForensicEventIds.bind(h.stateStore);
        h.stateStore.hasForensicEventIds = async (c, ids) => {
          if (armed) stop();
          return has(c, ids);
        };
      } else {
        const raw = ctx.rawSearch!;
        ctx.rawSearch = { ...raw, writable: async (c) => (stop(), raw.writable(c)) };
      }
      const chat = await h.run();
      expect(await h.inTimeline("raw1")).toBe(false);
      expect(chat.proposals.filter((p) => p.status === "pending")).toEqual([]);
      expect(lastTurn(chat).text).toBe(WATSON_CANCELLED_TEXT);
    },
  );

  it("a stop while Auto reads its control applies nothing (Codex #4)", async () => {
    const h = await oneStep([reply({ newQuestions: [q] })], { mode: "auto" });
    h.ctx.auto = {
      ...h.ctx.auto!,
      control: async () => {
        h.reg.cancel(CASE);
        return { watsonRunMode: "auto" };
      },
    };
    const chat = await h.run();
    expect(chat.proposals.find((p) => p.kind === "question_new")?.status).toBe("pending");
  });

  it("a stop between two Auto actions leaves the second for an analyst (Codex #4)", async () => {
    const q2 = { question: "Did rclone reach 203.0.113.7?", why: "the egress" };
    const h = await oneStep([reply({ newQuestions: [q, q2] })], { mode: "auto" });
    const add = h.deps.activity.add.bind(h.deps.activity);
    h.deps.activity.add = async (c: string, e: Parameters<typeof add>[1]) => {
      h.reg.cancel(CASE); // the first apply is running: it finishes
      return add(c, e);
    };
    const chat = await h.run();
    const asked = chat.proposals.filter((p) => p.kind === "question_new").map((p) => p.status);
    expect(asked).toEqual(["applied", "pending"]);
    expect(chat.turns.some((t) => t.text.includes("An analyst stopped Watson."))).toBe(true);
  });

  it.each(["forensic", "super"] as const)(
    "a stop before the %s hop starts its lookup (Codex #5)",
    async (kind) => {
      const ask = kind === "super" ? superLookup() : { lookup: { text: "rclone" } };
      let queries = 0;
      const h = await oneStep([reply(ask)], {
        onCall: (n) => void (n === 1 && h.reg.cancel(CASE)),
      });
      const raw = h.ctx.rawSearch!;
      const query: typeof raw.reader.query = (id, qq) => (queries++, raw.reader.query(id, qq));
      h.ctx.rawSearch = { ...raw, reader: { ...raw.reader, query } };
      const chat = await h.run();
      expect(h.provider.calls).toBe(1);
      expect(queries).toBe(0);
      expect(lastTurn(chat).text).toBe(WATSON_CANCELLED_TEXT);
    },
  );

  it("a cancelled reaction keeps the earlier failure count", async () => {
    const h = await oneStep([], { onCall: () => void h.reg.cancel(CASE) });
    const at = new Date().toISOString();
    await h.chatStore.update(CASE, (c) => ({
      ...c,
      analystEngaged: true,
      reactionFailures: 1,
      pendingCaseEvents: [{ kind: "notebook" as const, text: "a note", at }],
    }));
    const chat = await h.run("", { reaction: true });
    expect(lastTurn(chat).text).toBe(WATSON_CANCELLED_TEXT);
    expect(chat.reactionFailures).toBe(1);
  });
});

describe("the round's time limit (#2639)", () => {
  it("is twice the AI request timeout, read defensively, and safe for a timer", () => {
    expect(watsonRoundMaxMs({})).toBe(1_800_000);
    expect(watsonRoundMaxMs({ DFIR_AI_TIMEOUT_MS: "60000" })).toBe(120_000);
    for (const bad of ["", "abc", "-5", "0", "NaN"])
      expect(watsonRoundMaxMs({ DFIR_AI_TIMEOUT_MS: bad })).toBe(1_800_000);
    expect(watsonRoundMaxMs({ DFIR_AI_TIMEOUT_MS: "9e15" })).toBe(2_147_483_647);
  });

  it("a provider that never answers is stopped at the limit: the round saves the timeout note and ends", async () => {
    const before = process.env.DFIR_AI_TIMEOUT_MS;
    process.env.DFIR_AI_TIMEOUT_MS = "250"; // limit 500 ms
    try {
      const reg = new WatsonRunRegistry();
      // The abort lands while this waits. A slow CI runner may reach the limit even before the send:
      // either way the round stops with the timeout note and is never retried.
      const hang = () => new Promise<void>((r) => setTimeout(r, 3000));
      const p = new Scripted([abortAware(final())], { onSend: hang });
      const h = await toolHarness(p, { retries: 3, ctx: { runs: reg } });
      const chat = await h.run();
      expect(p.sent.length).toBeLessThanOrEqual(1); // never retried
      expect(lastTurn(chat)).toMatchObject({ role: "system", error: true });
      expect(lastTurn(chat).text).toMatch(
        /^Watson stopped this answer after 1 minute, because the round did not finish in time\./,
      );
      expect(reg.status(CASE)).toBeNull();
    } finally {
      if (before === undefined) delete process.env.DFIR_AI_TIMEOUT_MS;
      else process.env.DFIR_AI_TIMEOUT_MS = before;
    }
  });

  it("an analyst's stop wins over a later time limit, and an ended run cannot expire", () => {
    const reg = new WatsonRunRegistry();
    const a = reg.begin(CASE, { kind: "analyst" });
    reg.cancel(CASE);
    a.expire(new WatsonRoundTimedOut(60_000));
    expect(a.signal.reason).toBeInstanceOf(WatsonCancelled);
    expect(a.signal.reason).not.toBeInstanceOf(WatsonRoundTimedOut);
    const b = reg.begin(CASE, { kind: "analyst" });
    b.end();
    b.expire(new WatsonRoundTimedOut(60_000));
    expect(b.signal.aborted).toBe(false);
  });
});
