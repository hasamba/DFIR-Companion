import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ActivityLogStore, NewActivityEntry } from "../../../src/analysis/activityLog.js";
import { AnalysisPipeline } from "../../../src/analysis/pipeline.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import {
  applyWatsonProposal,
  WatsonProposalConflict,
  type WriterDeps,
} from "../../../src/analysis/ai/watson/proposals.js";
import type { WatsonEventPromoteProposal, WatsonPaste } from "../../../src/analysis/ai/watson/types.js";
import { emptyWatsonChat } from "../../../src/analysis/ai/watson/types.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type Finding, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import { WATSON_MARKER } from "../../../src/analysis/timeline/watsonItems.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// The event-promote writer: a row the content tagger graded above Info during a Watson paste ingest
// is held as a proposal. Apply promotes it into the forensic timeline at the raised grade with the
// Watson mark; undo removes only the rows that apply added, only while they are unchanged and no
// Watson finding cites them; an undone proposal may be applied again.

const CASE = "c1";

const paste: WatsonPaste = {
  id: "wf-1",
  storedName: "0001_hunt.json",
  filename: "hunt.json",
  bytes: 120,
  lines: 3,
  at: "2026-03-01T09:00:00Z",
};

const raised: ForensicEvent = {
  id: "ev-held-1",
  timestamp: "2026-03-01T08:05:00Z",
  description: "ntdsutil ifm create full on host vault.example.com",
  severity: "High",
  mitreTechniques: ["T1003.003"],
  relatedFindingIds: [],
  sourceScreenshots: [],
  provenance: [WATSON_MARKER],
};

const proposalOf = (events: ForensicEvent[] = [raised]): WatsonEventPromoteProposal => ({
  id: "wp-e",
  turnId: "t-sys",
  kind: "event_promote",
  targetId: events[0].id,
  events,
  pasteId: paste.id,
  status: "pending",
});

const watsonFinding = (cites: string): Finding => ({
  id: "f-watson-0a1b2c3d",
  author: "watson",
  severity: "High",
  title: "Credential store staged",
  description: "ntdsutil staged the directory database.",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: [],
  relatedEventIds: [cites],
  firstSeen: "2026-03-01T08:00:00Z",
  lastUpdated: "2026-03-01T09:00:00Z",
  status: "open",
});

describe("Watson event-promote writer", () => {
  let root: string;
  let stateStore: StateStore;
  let chatStore: WatsonChatStore;
  let entries: NewActivityEntry[];
  let outOfDate: string[];
  let deps: WriterDeps;

  const row = async (id: string) => (await stateStore.forensicRowsById(CASE, [id]))[0]?.event;
  const stored = async () =>
    (await chatStore.load(CASE)).proposals.find((p) => p.id === "wp-e") as WatsonEventPromoteProposal;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "watson-event-promote-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
    stateStore = new StateStore(cases);
    await stateStore.save(emptyState(CASE));
    chatStore = new WatsonChatStore(cases);
    await chatStore.save(CASE, { ...emptyWatsonChat(), pastes: [paste], proposals: [proposalOf()] });
    const stateLock = new StateLock();
    const pipeline = new AnalysisPipeline({
      stateStore,
      stateLock,
      imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    });
    entries = [];
    outOfDate = [];
    deps = {
      stateStore,
      stateLock,
      chatStore,
      activity: {
        add: async (_c: string, e: NewActivityEntry) => {
          entries.push(e);
          return e;
        },
      } as unknown as ActivityLogStore,
      cases,
      markConclusionsOutOfDate: async (_c, why) => {
        outOfDate.push(why);
      },
      promoteEvents: (caseId, events, opts) => pipeline.promoteSuperTimelineWithOutcome(caseId, events, opts),
    };
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("apply promotes the held row at the raised grade, marked as Watson's, and records what it added", async () => {
    await applyWatsonProposal(deps, CASE, "wp-e", "apply", "Ana");
    const ev = await row(raised.id);
    expect(ev?.severity).toBe("High");
    expect(ev?.mitreTechniques).toContain("T1003.003");
    expect(ev?.provenance).toContain(WATSON_MARKER);
    expect(ev?.promotedAt).toBeTruthy();
    const p = await stored();
    expect(p.status).toBe("applied");
    expect(p.createdEventIds).toEqual([raised.id]);
    expect(p.promotedAt).toBe(ev?.promotedAt);
    expect(outOfDate.length).toBe(1);
    expect(entries.map((e) => e.action)).toEqual(["watson.apply"]);
    const timeline = (await stateStore.loadOverview(CASE)).timeline;
    expect(timeline.some((t) => t.description.includes("Watson paste hunt.json"))).toBe(true);
  });

  it("undo removes the promoted row, and an undone proposal can be applied again", async () => {
    await applyWatsonProposal(deps, CASE, "wp-e", "apply", "Ana");
    await applyWatsonProposal(deps, CASE, "wp-e", "undo", "Ana");
    expect(await row(raised.id)).toBeUndefined();
    expect((await stored()).status).toBe("undone");
    await applyWatsonProposal(deps, CASE, "wp-e", "apply", "Ana");
    expect((await row(raised.id))?.severity).toBe("High");
    expect((await stored()).status).toBe("applied");
    expect(entries.map((e) => e.action)).toEqual(["watson.apply", "watson.undo", "watson.apply"]);
  });

  it("undo refuses while an applied Watson finding cites the row", async () => {
    await applyWatsonProposal(deps, CASE, "wp-e", "apply", "Ana");
    const overview = await stateStore.loadOverview(CASE);
    await stateStore.saveOverview({ ...overview, findings: [watsonFinding(raised.id)] });
    const undo = applyWatsonProposal(deps, CASE, "wp-e", "undo", "Ana");
    await expect(undo).rejects.toBeInstanceOf(WatsonProposalConflict);
    await expect(undo).rejects.toThrow(/undo the finding that cites it first/);
    expect(await row(raised.id)).toBeDefined();
    expect((await stored()).status).toBe("applied");
  });

  it("undo refuses a row whose grade changed since it was applied", async () => {
    await applyWatsonProposal(deps, CASE, "wp-e", "apply", "Ana");
    const [r] = await stateStore.forensicRowsById(CASE, [raised.id]);
    await stateStore.deleteForensicRows(CASE, [r.rowId]);
    await stateStore.appendForensicEvents(CASE, [{ ...r.event, severity: "Low" }]);
    await expect(applyWatsonProposal(deps, CASE, "wp-e", "undo", "Ana")).rejects.toBeInstanceOf(
      WatsonProposalConflict,
    );
    expect((await row(raised.id))?.severity).toBe("Low");
  });

  it("does not delete a row that was already in the forensic timeline before apply", async () => {
    await stateStore.appendForensicEvents(CASE, [{ ...raised, provenance: [] }]);
    await applyWatsonProposal(deps, CASE, "wp-e", "apply", "Ana");
    expect((await stored()).createdEventIds).toEqual([]);
    await applyWatsonProposal(deps, CASE, "wp-e", "undo", "Ana");
    expect(await row(raised.id)).toBeDefined();
  });

  it("an undone proposal of another kind still cannot be applied again", async () => {
    const q = {
      id: "wp-q",
      turnId: "t1",
      kind: "next_step_new" as const,
      targetId: "ns-1",
      after: {
        id: "ns-1",
        action: "Collect the DC logs",
        priority: "high" as const,
        rationale: "r",
        pointer: "dc",
      },
      status: "undone" as const,
    };
    await chatStore.update(CASE, (c) => ({ ...c, proposals: [...c.proposals, q] }));
    await expect(applyWatsonProposal(deps, CASE, "wp-q", "apply", "Ana")).rejects.toThrow(
      /Cannot apply a proposal that is undone/,
    );
  });
});
