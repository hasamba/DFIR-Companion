import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../../../src/analysis/activityLog.js";
import { autoApply } from "../../../../src/analysis/ai/watson/autoApply.js";
import { WatsonChatStore } from "../../../../src/analysis/ai/watson/chatStore.js";
import {
  checkCsSearch,
  csSearchKey,
  CS_ALREADY_RAN,
} from "../../../../src/analysis/ai/watson/crowdstrike/csLaunchCheck.js";
import { withCsSearch } from "../../../../src/analysis/ai/watson/crowdstrike/csSearchProposals.js";
import { withCsResult } from "../../../../src/analysis/ai/watson/crowdstrike/csSearchWatch.js";
import { applyWatsonProposal, type WriterDeps } from "../../../../src/analysis/ai/watson/proposals.js";
import { sanitizeWatsonReply, watsonReplySchema } from "../../../../src/analysis/ai/watson/replySchema.js";
import { buildWatsonUserPrompt } from "../../../../src/analysis/ai/watson/promptBuilder.js";
import type { Outcome } from "../../../../src/analysis/ai/watson/roundOutcome.js";
import {
  emptyWatsonChat,
  type WatsonCsSearchProposal,
  type WatsonProposal,
} from "../../../../src/analysis/ai/watson/types.js";
import { fingerprintStoreFor } from "../../../../src/analysis/ai/watson/velo/fingerprintIndex.js";
import type { CsSearchRequest } from "../../../../src/analysis/ai/watson/writers/csSearchWriter.js";
import { SIEM_DEFAULTS } from "../../../../src/analysis/siemSearch.js";
import { StateLock } from "../../../../src/analysis/stateLock.js";
import { StateStore } from "../../../../src/analysis/stateStore.js";
import { emptyState } from "../../../../src/analysis/stateTypes.js";
import { CaseStore } from "../../../../src/storage/caseStore.js";

// #2666 Part B: Watson's CrowdStrike Next-Gen SIEM search — the launch check, the card, running it,
// its result event, Auto mode, the reply sanitizer and the prompt block. No network: the job start is
// a fake that records what it was given.

const CASE = "c1";
const TURN = "wt-round";
const NOW = Date.parse("2026-11-17T12:34:00.000Z");
const DAY = 86_400_000;
const Q = `#event_simpleName=ProcessRollup2\n| CommandLine=/-enc/i\n| table([@timestamp, ComputerName, CommandLine], limit=500)`;
const START = "2026-11-14T00:00:00.000Z";
const END = "2026-11-16T00:00:00.000Z";
const LIMITS = { ...SIEM_DEFAULTS };
const ENV = { DFIR_CROWDSTRIKE_SIEM_CLIENT_ID: "id", DFIR_CROWDSTRIKE_SIEM_CLIENT_SECRET: "secret" };

describe("checkCsSearch", () => {
  it("passes a CQL query inside the window and keys it by query + repository + range", () => {
    const r = checkCsSearch({ query: Q, start: START, end: END }, LIMITS, new Set(), NOW);
    expect(r).toEqual({ ok: true, start: START, end: END, key: csSearchKey(Q, "search-all", START, END) });
  });

  it("refuses a query that is not CQL", () => {
    const r = checkCsSearch(
      { query: "SELECT * FROM pslist()", start: START, end: END },
      LIMITS,
      new Set(),
      NOW,
    );
    expect(r).toMatchObject({ ok: false, reason: "The query is not CrowdStrike CQL." });
  });

  it("refuses a range over the window cap, naming it", () => {
    const r = checkCsSearch(
      { query: Q, start: "2026-11-01T00:00:00.000Z", end: END },
      LIMITS,
      new Set(),
      NOW,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("The limit is 7 days");
  });

  it("refuses a search that already ran (same query, repository and range)", () => {
    const ran = new Set([csSearchKey(Q, "search-all", START, END)]);
    expect(checkCsSearch({ query: Q, start: START, end: END }, LIMITS, ran, NOW)).toMatchObject({
      ok: false,
      reason: CS_ALREADY_RAN,
      duplicate: true,
    });
    // The same hunt over another window is a new search.
    expect(
      checkCsSearch({ query: Q, start: "2026-11-15T00:00:00.000Z", end: END }, LIMITS, ran, NOW).ok,
    ).toBe(true);
  });

  it("with no range, searches the last N days up to the current hour", () => {
    const r = checkCsSearch({ query: Q }, LIMITS, new Set(), NOW);
    expect(r).toMatchObject({ ok: true, end: "2026-11-17T12:00:00.000Z" });
    if (r.ok) expect(Date.parse(r.end) - Date.parse(r.start)).toBe(7 * DAY);
  });

  it("refuses hidden characters and a range with one bound only", () => {
    expect(checkCsSearch({ query: `${Q}‮`, start: START, end: END }, LIMITS, new Set(), NOW).ok).toBe(false);
    expect(checkCsSearch({ query: Q, start: START }, LIMITS, new Set(), NOW).ok).toBe(false);
  });
});

describe("reply sanitizer and prompt block", () => {
  const reply = (request: unknown) =>
    watsonReplySchema.parse({ message: "m", request }) as Parameters<typeof sanitizeWatsonReply>[0];
  const req = {
    kind: "crowdstrike_search",
    title: "Encoded PowerShell",
    query: Q,
    start: START,
    end: END,
    why: "w",
  };

  it("keeps the search when the SIEM client is set up", () => {
    const out = sanitizeWatsonReply(reply(req), new Set(), new Set(), new Set(), undefined, false, true);
    expect(out.request).toMatchObject({ kind: "crowdstrike_search", query: Q, start: START, end: END });
  });

  it("without the client the same CQL becomes a copy-ready query", () => {
    const out = sanitizeWatsonReply(reply(req), new Set(), new Set(), new Set());
    expect(out.request).toEqual({ kind: "query", language: "cql", query: Q, why: "w" });
  });

  it("the prompt mentions the tool only when it is set up", () => {
    const base = {
      state: { ...emptyState(CASE), keyQuestions: [] },
      chat: emptyWatsonChat(),
      analystText: "go",
      caseContext: "",
      mainLanguages: ["cql"],
    };
    expect(buildWatsonUserPrompt(base)).not.toContain("crowdstrike_search");
    const on = buildWatsonUserPrompt({ ...base, crowdstrike: LIMITS });
    expect(on).toContain("CROWDSTRIKE NG-SIEM");
    expect(on).toContain('"kind": "crowdstrike_search"');
    expect(on).toContain("at most 7 days");
  });
});

let cases: CaseStore;
let chatStore: WatsonChatStore;
let activity: ActivityLogStore;
let stateStore: StateStore;
let started: Array<{ req: CsSearchRequest; proposalId: string }>;
let startFails: boolean;
let repository: string;
let priorJob: { jobId: string; status: "running" | "interrupted" } | undefined;

beforeEach(async () => {
  cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-cs-")));
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  await stateStore.save(emptyState(CASE));
  chatStore = new WatsonChatStore(cases);
  activity = new ActivityLogStore(cases);
  started = [];
  startFails = false;
  repository = "search-all";
  priorJob = undefined;
});

function deps(): WriterDeps {
  return {
    stateStore,
    stateLock: new StateLock(),
    chatStore,
    activity,
    markConclusionsOutOfDate: async () => {},
    csSearch: {
      limits: () => ({ ...LIMITS, repository }),
      start: async (_caseId, req, _actor, proposalId) => {
        if (startFails) throw new Error("the job ledger refused it");
        started.push({ req, proposalId });
        return { jobId: `job-${started.length}` };
      },
      fingerprints: fingerprintStoreFor(cases),
      jobFor: () => priorJob,
    },
  };
}

const outcomeWith = (request: unknown): Outcome =>
  ({ reply: { message: "m", request }, shownEvents: [], questions: [] }) as unknown as Outcome;
const seams = () => ({ cases, chatStore });

function card(over: Partial<WatsonCsSearchProposal> = {}): WatsonCsSearchProposal {
  const end = new Date(NOW - DAY).toISOString();
  const start = new Date(NOW - 3 * DAY).toISOString();
  return {
    id: "wp-cs",
    turnId: TURN,
    kind: "cs_search",
    status: "pending",
    targetId: csSearchKey(Q, "search-all", start, end),
    title: "Encoded PowerShell",
    query: Q,
    start,
    end,
    repository: "search-all",
    ...over,
  };
}

async function seed(proposals: WatsonProposal[]): Promise<void> {
  const turns = [
    { id: TURN, at: START, role: "watson" as const, text: "now", proposalIds: proposals.map((p) => p.id) },
  ];
  await chatStore.update(CASE, (c) => ({ ...c, turns, proposals }));
}

describe("withCsSearch: the card", () => {
  const req = {
    kind: "crowdstrike_search",
    title: "Encoded PowerShell",
    query: `${Q}  `,
    start: START,
    end: END,
    why: "w",
  };

  it("makes a pending card whose query is byte-identical to the request", async () => {
    const out = await withCsSearch(seams(), CASE, outcomeWith(req), true, ENV, NOW);
    expect(out.csProposal).toMatchObject({
      kind: "cs_search",
      status: "pending",
      query: `${Q}  `,
      start: START,
      end: END,
      repository: "search-all",
    });
    expect(out.csNote).toBeUndefined();
  });

  it("makes no card for a non-CQL, out-of-window or repeated search — the turn says why", async () => {
    const bad = await withCsSearch(
      seams(),
      CASE,
      outcomeWith({ ...req, query: "index=main | stats count" }),
      true,
      ENV,
      NOW,
    );
    expect(bad.csProposal).toBeUndefined();
    expect(bad.csNote).toContain("Nothing to approve");
    const wide = await withCsSearch(
      seams(),
      CASE,
      outcomeWith({ ...req, start: "2026-10-01T00:00:00.000Z" }),
      true,
      ENV,
      NOW,
    );
    expect(wide.csProposal).toBeUndefined();
    await fingerprintStoreFor(cases).add(CASE, [csSearchKey(req.query, "search-all", START, END)]);
    const again = await withCsSearch(seams(), CASE, outcomeWith(req), true, ENV, NOW);
    expect(again.csProposal).toBeUndefined();
    expect(again.csNote).toContain(CS_ALREADY_RAN);
  });

  it("makes no card when the SIEM client is not set up", async () => {
    const out = await withCsSearch(seams(), CASE, outcomeWith(req), true, {}, NOW);
    expect(out.csProposal).toBeUndefined();
    expect(out.csNote).toContain("not set up");
  });
});

describe("applying a cs_search card", () => {
  it("starts the job with the card's query byte-for-byte and saves applied with the job id", async () => {
    await seed([card()]);
    const { chat } = await applyWatsonProposal(deps(), CASE, "wp-cs", "apply", "Dana");
    expect(started).toHaveLength(1);
    expect(started[0].req.query).toBe(Q);
    expect(started[0].proposalId).toBe("wp-cs");
    const p = chat.proposals[0] as WatsonCsSearchProposal;
    expect(p).toMatchObject({
      status: "applied",
      launched: { jobId: "job-1", by: "Dana" },
      watch: { state: "running" },
    });
    // The key is reserved: running it twice is refused.
    await seed([card({ id: "wp-cs2" })]);
    await expect(applyWatsonProposal(deps(), CASE, "wp-cs2", "apply")).rejects.toThrow(CS_ALREADY_RAN);
  });

  it("refuses when Settings changed the repository after the card was made", async () => {
    repository = "other_repo";
    await seed([card()]);
    await expect(applyWatsonProposal(deps(), CASE, "wp-cs", "apply")).rejects.toThrow(/repository changed/);
    expect(started).toHaveLength(0);
  });

  it("a job that does not start leaves the card pending and releases its key", async () => {
    startFails = true;
    await seed([card()]);
    await expect(applyWatsonProposal(deps(), CASE, "wp-cs", "apply")).rejects.toThrow(/did not start/);
    expect((await chatStore.load(CASE)).proposals[0].status).toBe("pending");
    expect((await fingerprintStoreFor(cases).load(CASE)).has(card().targetId)).toBe(false);
  });

  it("a card whose job already started (its save was lost) records that job and starts no second search", async () => {
    priorJob = { jobId: "job-earlier", status: "interrupted" };
    await seed([card()]);
    const { chat } = await applyWatsonProposal(deps(), CASE, "wp-cs", "apply", "Dana");
    expect(started).toHaveLength(0);
    const p = chat.proposals[0] as WatsonCsSearchProposal;
    expect(p).toMatchObject({
      status: "applied",
      launched: { jobId: "job-earlier" },
      watch: { state: "failed" },
    });
    expect(p.watch?.text).toContain("ended as interrupted");
  });

  it("cannot be undone", async () => {
    await seed([card()]);
    await applyWatsonProposal(deps(), CASE, "wp-cs", "apply");
    await expect(applyWatsonProposal(deps(), CASE, "wp-cs", "undo")).rejects.toThrow(/cannot undo/);
  });
});

describe("withCsResult: the result event", () => {
  it("saves the outcome on the card and notes one hunt event, only once", () => {
    const chat = {
      ...emptyWatsonChat(),
      proposals: [card({ status: "applied", launched: { jobId: "j", at: START, by: "a" } })],
    };
    const outcome = {
      title: "Encoded PowerShell",
      rows: 12,
      events: 12,
      added: 3,
      truncated: false,
      timedOut: false,
    };
    const r = withCsResult(chat, "wp-cs", outcome, START);
    expect(r.sent).toBe(true);
    expect(r.chat.pendingCaseEvents.at(-1)).toMatchObject({
      kind: "hunt",
      text: "Watson's CrowdStrike NG-SIEM search Encoded PowerShell finished. It found 12 rows and added 3 new events",
    });
    expect((r.chat.proposals[0] as WatsonCsSearchProposal).watch).toMatchObject({
      state: "finished",
      rows: 12,
      added: 3,
      notified: true,
    });
    expect(withCsResult(r.chat, "wp-cs", outcome, START).sent).toBe(false);
  });

  it("a result for a card left pending (lost save) is kept: the card turns applied, one event", () => {
    const chat = { ...emptyWatsonChat(), proposals: [card()] };
    const outcome = { title: "t", rows: 2, events: 2, added: 1, truncated: false, timedOut: false };
    const r = withCsResult(chat, "wp-cs", outcome, START);
    expect(r.sent).toBe(true);
    expect(r.chat.proposals[0]).toMatchObject({
      status: "applied",
      watch: { state: "finished", notified: true },
    });
  });

  it("a capped search says the row cap cut the rest", () => {
    const chat = { ...emptyWatsonChat(), proposals: [card({ status: "applied" })] };
    const outcome = { title: "t", rows: 10_000, events: 10_000, added: 4, truncated: true, timedOut: false };
    expect(withCsResult(chat, "wp-cs", outcome, START).chat.pendingCaseEvents.at(-1)?.text).toContain(
      "imported the first 10000 rows (the row cap cut the rest)",
    );
  });
});

describe("Auto mode", () => {
  const AUTO_ON = {
    watsonRunMode: "auto" as const,
    watsonAutoSince: START,
    watsonAutoBy: { name: "Robin Lead" },
  };

  it("runs a card that passed the check from an analyst's message in the Watson panel", async () => {
    await seed([card()]);
    const chat = await autoApply(
      deps(),
      CASE,
      { turnId: TURN, reaction: false, source: "dashboard" },
      AUTO_ON,
    );
    expect(started).toHaveLength(1);
    expect(chat.turns.at(-1)?.text).toContain("Started CrowdStrike NG-SIEM search: Encoded PowerShell");
  });

  it("leaves it for the analyst from a reaction round or a chat-bot command", async () => {
    await seed([card()]);
    const chat = await autoApply(deps(), CASE, { turnId: TURN, reaction: true }, AUTO_ON);
    expect(started).toHaveLength(0);
    expect(chat.turns.at(-1)?.text).toContain("only from a message in the Watson panel");
    await autoApply(deps(), CASE, { turnId: TURN, reaction: false, source: "slash" }, AUTO_ON);
    expect(started).toHaveLength(0);
  });
});
