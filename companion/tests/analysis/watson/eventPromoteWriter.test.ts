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
import {
  eventPromoteWriter,
  promoteRows,
} from "../../../src/analysis/ai/watson/writers/eventPromoteWriter.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type Finding, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import { WATSON_MARKER } from "../../../src/analysis/timeline/watsonItems.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// The proposals' turns are in the chat: a settled proposal whose turn left the chat is dropped (F11).
const chatWithTurns = () => ({
  ...emptyWatsonChat(),
  turns: ["t1", "t2", "t-sys"].map((id) => ({
    id,
    at: "2026-03-01T09:00:00Z",
    role: "watson" as const,
    text: "",
  })),
});

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
    await chatStore.save(CASE, { ...chatWithTurns(), pastes: [paste], proposals: [proposalOf()] });
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
    await expect(undo).rejects.toThrow(/Undo that finding first/);
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
    await stateStore.appendForensicEvents(CASE, [{ ...raised, severity: "Low", provenance: [] }]);
    await applyWatsonProposal(deps, CASE, "wp-e", "apply", "Ana");
    expect((await stored()).createdEventIds).toEqual([]);
    // Not re-graded and not marked: the row the case gained meanwhile is left as it was.
    expect((await row(raised.id))?.severity).toBe("Low");
    expect((await row(raised.id))?.provenance ?? []).not.toContain(WATSON_MARKER);
    await applyWatsonProposal(deps, CASE, "wp-e", "undo", "Ana");
    expect(await row(raised.id)).toBeDefined();
  });

  it("marks only the rows it merged, never a requested row the case already held (F8)", async () => {
    const second: ForensicEvent = {
      ...raised,
      id: "ev-held-2",
      description: "reg save HKLM\\SAM on host vault.example.com",
      mitreTechniques: ["T1003.002"],
    };
    await chatStore.save(CASE, {
      ...chatWithTurns(),
      pastes: [paste],
      proposals: [proposalOf([raised, second])],
    });
    await stateStore.appendForensicEvents(CASE, [{ ...raised, severity: "Low", provenance: [] }]);
    await applyWatsonProposal(deps, CASE, "wp-e", "apply", "Ana");
    expect((await stored()).createdEventIds).toEqual([second.id]);
    expect((await row(second.id))?.provenance).toContain(WATSON_MARKER);
    expect((await row(raised.id))?.provenance ?? []).not.toContain(WATSON_MARKER);
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
      /You cannot apply a proposal that is undone/,
    );
  });

  it("the applied row keeps the held copy's cap and engine start-up records", async () => {
    const recorded = {
      ...raised,
      severity: "Low",
      buildTime: {
        marker: "sysprep",
        window: "2026-03-01T08:00:00.000Z/2026-03-01T09:00:00.000Z",
        cappedFrom: "High",
      },
      labSetup: { tag: "lab-setup", folder: "\\labdrop\\", cappedFrom: "High" },
      defenderEngineBoot: { bootAt: "2026-03-01T08:04:00.000Z" },
    } as ForensicEvent;
    await chatStore.save(CASE, {
      ...chatWithTurns(),
      pastes: [paste],
      proposals: [proposalOf([recorded])],
    });
    await applyWatsonProposal(deps, CASE, "wp-e", "apply", "Ana");
    const ev = (await row(raised.id)) as ForensicEvent & Record<string, unknown>;
    expect(ev.severity).toBe("Low");
    expect(ev.buildTime).toEqual(recorded.buildTime);
    expect(ev.labSetup).toEqual({ tag: "lab-setup", folder: "\\labdrop\\", cappedFrom: "High" });
    expect(ev.defenderEngineBoot).toEqual({ bootAt: "2026-03-01T08:04:00.000Z" });
    // Undo still recognises the row as it landed.
    await applyWatsonProposal(deps, CASE, "wp-e", "undo", "Ana");
    expect(await row(raised.id)).toBeUndefined();
  });

  it("undo refuses while any finding cites the row, not only a Watson one", async () => {
    await applyWatsonProposal(deps, CASE, "wp-e", "apply", "Ana");
    const { author: _a, ...analyst } = watsonFinding(raised.id);
    const overview = await stateStore.loadOverview(CASE);
    await stateStore.saveOverview({ ...overview, findings: [{ ...analyst, id: "f-1" }] });
    const undo = applyWatsonProposal(deps, CASE, "wp-e", "undo", "Ana");
    await expect(undo).rejects.toBeInstanceOf(WatsonProposalConflict);
    await expect(undo).rejects.toThrow(/Finding f-1 cites event/);
    expect(await row(raised.id)).toBeDefined();
    expect((await stored()).status).toBe("applied");
  });

  // Phase 4 (D9): the same record carries the super-timeline rows Watson cited.
  const superProposal = (promotedAt?: string): WatsonEventPromoteProposal => ({
    id: "wp-s",
    turnId: "t1",
    kind: "event_promote",
    targetId: raised.id,
    events: [{ ...raised, severity: "Info", provenance: [] }],
    source: "supertimeline",
    status: "pending",
    ...(promotedAt ? { promotedAt } : {}),
  });

  it("a super-timeline promotion writes its own timeline note and reads no paste", async () => {
    const noChat = {
      ...deps,
      chatStore: {
        load: async () => {
          throw new Error("the chat must not be read");
        },
      } as unknown as WriterDeps["chatStore"],
    };
    const { proposal } = await eventPromoteWriter.apply(
      noChat,
      CASE,
      superProposal("2026-11-14T10:00:00.000Z"),
    );
    expect(proposal?.createdEventIds).toEqual([raised.id]);
    expect(proposal?.promotedAt).toBe("2026-11-14T10:00:00.000Z");
    expect((await row(raised.id))?.severity).toBe("Info");
    const timeline = (await stateStore.loadOverview(CASE)).timeline;
    expect(timeline.some((t) => t.description.includes("Watson cited 1 super-timeline row"))).toBe(true);
    expect(timeline.some((t) => t.description.includes("Watson paste"))).toBe(false);
    expect(outOfDate).toEqual(["Watson promoted super-timeline rows it cited"]);
  });

  it("promoteRows adopts rows already stamped with the proposal's promotedAt (recovery is idempotent)", async () => {
    const p = superProposal("2026-11-14T10:00:00.000Z");
    const first = await promoteRows(deps, CASE, p);
    expect(first.proposal.createdEventIds).toEqual([raised.id]);
    // The record was lost after the rows landed: the retry finds them and adopts them.
    const again = await promoteRows(deps, CASE, p);
    expect(again.proposal.createdEventIds).toEqual([raised.id]);
    expect(again.proposal.landedRows).toEqual(first.proposal.landedRows);
    expect(outOfDate).toEqual([]);
    // A Watson row stamped by another promotion is not this proposal's to adopt.
    const other = await promoteRows(deps, CASE, superProposal("2026-11-14T11:00:00.000Z"));
    expect(other.proposal.createdEventIds).toEqual([]);
  });

  it("an old chat file's paste promotion, and a super-timeline one, both load", async () => {
    await chatStore.save(CASE, {
      ...chatWithTurns(),
      pastes: [paste],
      proposals: [
        proposalOf(),
        { ...superProposal("2026-11-14T10:00:00.000Z"), rawEvidenceIds: ["x"] } as never,
      ],
    });
    const loaded = (await chatStore.load(CASE)).proposals;
    expect(loaded.map((p) => p.id)).toEqual(["wp-e", "wp-s"]);
    expect(loaded[0]).toMatchObject({ pasteId: paste.id });
    expect(loaded[1]).toMatchObject({ source: "supertimeline", promotedAt: "2026-11-14T10:00:00.000Z" });
    expect("pasteId" in loaded[1]).toBe(false);
  });
});
