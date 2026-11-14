import { mkdtemp, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ActivityLogStore, NewActivityEntry } from "../../../src/analysis/activityLog.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import {
  applyWatsonProposal,
  WatsonProposalConflict,
  type WriterDeps,
} from "../../../src/analysis/ai/watson/proposals.js";
import type { WatsonFindingProposal, WatsonPaste } from "../../../src/analysis/ai/watson/types.js";
import { pasteLineEvent } from "../../../src/analysis/ai/watson/writers/pasteLineEvents.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type Finding, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import { WATSON_MARKER } from "../../../src/analysis/timeline/watsonItems.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// The finding writer against a real case database: a Watson finding cites a forensic event and a
// line of a stored paste, carries the Watson mark, and undoes back to exactly the case it found.

const CASE = "c1";
const FID = "f-watson-0a1b2c3d";
const HOSTILE = `=HYPERLINK("http://bad.example.com") <script>alert(1)</script> | a`;
const LINES = [
  "2026-03-01 08:00:00 mailer.example.com accepted message",
  "2026-03-01T08:05:10Z powershell -enc dGVzdA== on host wkstn-blue",
  HOSTILE,
];

const paste: WatsonPaste = {
  id: "wf-1",
  storedName: "watson-paste-1.txt",
  filename: "mail.log",
  bytes: 200,
  lines: LINES.length,
  at: "2026-03-01T09:00:00Z",
};

const e1: ForensicEvent = {
  id: "e1",
  timestamp: "2026-03-01T08:05:00Z",
  description: "powershell launched by winword",
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
};

const draft: Finding = {
  id: FID,
  severity: "High",
  title: "Encoded PowerShell after the phishing mail",
  description: "The mail from mailer.example.com was followed by encoded PowerShell.",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: ["T1059.001"],
  relatedEventIds: ["e1"],
  citedPasteLines: [{ pasteId: "wf-1", line: 2 }],
  firstSeen: "2026-03-01T08:00:00Z",
  lastUpdated: "2026-03-01T09:00:00Z",
  status: "open",
};

const findingNew = (after: Finding = draft): WatsonFindingProposal => ({
  id: "wp-f",
  turnId: "t1",
  kind: "finding_new",
  targetId: after.id,
  after,
  pasteLineEvents: (after.citedPasteLines ?? []).map((c) =>
    pasteLineEvent(paste, c.line, LINES[c.line - 1] ?? "", after.severity, after.id),
  ),
  status: "pending",
});

const PASTE_EV = "ev-watson-wf-1-2";

describe("Watson finding writer", () => {
  let root: string;
  let cases: CaseStore;
  let stateStore: StateStore;
  let chatStore: WatsonChatStore;
  let entries: NewActivityEntry[];
  let outOfDate: string[];
  let deps: WriterDeps;

  const seedChat = (...proposals: WatsonFindingProposal[]) =>
    chatStore.save(CASE, { ...emptyChat(), pastes: [paste], proposals });
  // The proposals' turns are in the chat: a settled proposal whose turn left the chat is dropped (F11).
  const emptyChat = () => ({
    turns: ["t1", "t2"].map((id) => ({ id, at: "2026-03-01T09:00:00Z", role: "watson" as const, text: "" })),
    proposals: [],
    pastes: [],
    unreadPasteIds: [],
    memory: "",
    pendingCaseEvents: [],
    costUSD: 0,
    tokens: 0,
    calls: 0,
  });
  const row = async (id: string) => (await stateStore.forensicRowsById(CASE, [id]))[0]?.event;
  const findings = async () => (await stateStore.loadOverview(CASE)).findings;
  const proposal = async (id = "wp-f") =>
    (await chatStore.load(CASE)).proposals.find((p) => p.id === id) as WatsonFindingProposal;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "watson-finding-writer-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
    stateStore = new StateStore(cases);
    await stateStore.save({ ...emptyState(CASE), forensicTimeline: [e1] });
    await writeFile(join(cases.importsDir(CASE), paste.storedName), LINES.join("\n"));
    chatStore = new WatsonChatStore(cases);
    await seedChat(findingNew());
    entries = [];
    outOfDate = [];
    const activity = {
      add: async (_c: string, e: NewActivityEntry) => {
        entries.push(e);
        return e;
      },
    } as unknown as ActivityLogStore;
    deps = {
      stateStore,
      stateLock: new StateLock(),
      chatStore,
      activity,
      cases,
      markConclusionsOutOfDate: async (_c, why) => {
        outOfDate.push(why);
      },
    };
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("apply writes a marked finding citing the event and the paste line, and links both rows", async () => {
    const out = await applyWatsonProposal(deps, CASE, "wp-f", "apply", "alice");
    const [f] = await findings();
    expect(f).toMatchObject({ id: FID, author: "watson", status: "open", approvedBy: "alice" });
    expect(f.relatedEventIds).toEqual(["e1", PASTE_EV]);
    expect(f.citedPasteLines).toEqual([{ pasteId: "wf-1", line: 2 }]);
    const ev = await row(PASTE_EV);
    expect(ev?.promotedAt).toBeTruthy();
    expect(ev?.provenance).toContain(WATSON_MARKER);
    expect(ev?.relatedFindingIds).toEqual([FID]);
    expect(ev?.severity).toBe("High");
    expect(ev?.timestamp).toBe("2026-03-01T08:05:10.000Z");
    expect(ev?.description).toBe(`Pasted mail.log line 2: ${LINES[1]}`);
    expect((await row("e1"))?.relatedFindingIds).toEqual([FID]);
    const p = await proposal();
    expect(p).toMatchObject({ status: "applied", appliedBy: "alice", createdEventIds: [PASTE_EV] });
    expect(p.appliedAt).toBeTruthy();
    expect(p.promotedAt).toBe(ev?.promotedAt);
    expect(out.state?.findings.map((x) => x.id)).toEqual([FID]);
    expect(outOfDate).toEqual(["Watson wrote a finding"]);
    expect(entries).toEqual([
      expect.objectContaining({
        action: "watson.apply",
        targetType: "finding",
        targetId: FID,
        actor: "alice",
      }),
    ]);
  });

  it("undo restores the case exactly: no finding, no paste row, the cited event unlinked", async () => {
    const stored = await row("e1");
    await applyWatsonProposal(deps, CASE, "wp-f", "apply");
    await applyWatsonProposal(deps, CASE, "wp-f", "undo");
    expect(await findings()).toEqual([]);
    expect(await row(PASTE_EV)).toBeUndefined();
    expect(await row("e1")).toEqual(stored);
    expect((await proposal()).status).toBe("undone");
    expect(outOfDate).toEqual(["Watson wrote a finding", "Watson wrote a finding"]);
    expect(entries.map((e) => e.action)).toEqual(["watson.apply", "watson.undo"]);
  });

  it("undo after the analyst dismissed the finding conflicts and changes nothing", async () => {
    await applyWatsonProposal(deps, CASE, "wp-f", "apply");
    const overview = await stateStore.loadOverview(CASE);
    await stateStore.saveOverview({
      ...overview,
      findings: overview.findings.map((f) => ({ ...f, status: "dismissed" as const })),
    });
    await expect(applyWatsonProposal(deps, CASE, "wp-f", "undo")).rejects.toBeInstanceOf(
      WatsonProposalConflict,
    );
    expect((await findings())[0]).toMatchObject({ id: FID, status: "dismissed" });
    expect(await row(PASTE_EV)).toBeDefined();
    expect((await row("e1"))?.relatedFindingIds).toEqual([FID]);
    expect((await proposal()).status).toBe("applied");
    expect(outOfDate).toHaveLength(1);
  });

  it("apply after the cited event was deleted and the paste file removed conflicts", async () => {
    const [r] = await stateStore.forensicRowsById(CASE, ["e1"]);
    await stateStore.deleteForensicRows(CASE, [r.rowId]);
    await unlink(join(cases.importsDir(CASE), paste.storedName));
    const err = await applyWatsonProposal(deps, CASE, "wp-f", "apply").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(WatsonProposalConflict);
    expect((err as Error).message).toBe("the cited evidence is gone");
    expect(await findings()).toEqual([]);
    expect(await row(PASTE_EV)).toBeUndefined();
    expect((await proposal()).status).toBe("pending");
    expect(entries).toEqual([]);
    expect(outOfDate).toEqual([]);
  });

  it("apply keeps only the live citations, and undo still matches what was written", async () => {
    await seedChat(
      findingNew({
        ...draft,
        relatedEventIds: ["e1", "e-gone"],
        citedPasteLines: [{ pasteId: "wf-1", line: 9 }],
      }),
    );
    const stored = await row("e1");
    await applyWatsonProposal(deps, CASE, "wp-f", "apply");
    const [f] = await findings();
    expect(f.relatedEventIds).toEqual(["e1"]);
    expect(f.citedPasteLines).toBeUndefined();
    expect((await proposal()).createdEventIds).toEqual([]);
    await applyWatsonProposal(deps, CASE, "wp-f", "undo");
    expect(await findings()).toEqual([]);
    expect(await row("e1")).toEqual(stored);
  });

  it("a hostile pasted line is stored verbatim in the event description", async () => {
    await seedChat(findingNew({ ...draft, citedPasteLines: [{ pasteId: "wf-1", line: 3 }] }));
    await applyWatsonProposal(deps, CASE, "wp-f", "apply");
    expect((await row("ev-watson-wf-1-3"))?.description).toBe(`Pasted mail.log line 3: ${HOSTILE}`);
  });

  it("undo after an import undo removed the row Watson added conflicts: no longer in the case", async () => {
    await applyWatsonProposal(deps, CASE, "wp-f", "apply");
    const [r] = await stateStore.forensicRowsById(CASE, [PASTE_EV]);
    await stateStore.deleteForensicRows(CASE, [r.rowId]);
    const err = await applyWatsonProposal(deps, CASE, "wp-f", "undo").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(WatsonProposalConflict);
    expect((err as Error).message).toMatch(/no longer in the case/);
    expect(await findings()).toHaveLength(1);
    expect((await row("e1"))?.relatedFindingIds).toEqual([FID]);
  });

  it("undo after a state restore removed the finding conflicts: no longer in the case", async () => {
    await applyWatsonProposal(deps, CASE, "wp-f", "apply");
    await stateStore.saveOverview({ ...(await stateStore.loadOverview(CASE)), findings: [] });
    await expect(applyWatsonProposal(deps, CASE, "wp-f", "undo")).rejects.toThrow(/no longer in the case/);
    expect(await row(PASTE_EV)).toBeDefined();
  });

  it("undo refuses while another finding cites the row Watson added", async () => {
    await applyWatsonProposal(deps, CASE, "wp-f", "apply");
    const overview = await stateStore.loadOverview(CASE);
    const other: Finding = { ...draft, id: "f-analyst", title: "Analyst view", relatedEventIds: [PASTE_EV] };
    await stateStore.saveOverview({ ...overview, findings: [...overview.findings, other] });
    await expect(applyWatsonProposal(deps, CASE, "wp-f", "undo")).rejects.toBeInstanceOf(
      WatsonProposalConflict,
    );
    expect(await row(PASTE_EV)).toBeDefined();
    expect((await findings()).map((f) => f.id)).toEqual([FID, "f-analyst"]);
  });

  it("a paste row that existed before the apply is linked, never created, and survives undo", async () => {
    const prior = pasteLineEvent(paste, 2, LINES[1], "Medium", "f-earlier", "2026-03-01T09:30:00Z");
    await stateStore.appendForensicEvents(CASE, [prior]);
    const stored = await row(PASTE_EV);
    await applyWatsonProposal(deps, CASE, "wp-f", "apply");
    expect((await proposal()).createdEventIds).toEqual([]);
    expect((await row(PASTE_EV))?.relatedFindingIds).toEqual(["f-earlier", FID]);
    await applyWatsonProposal(deps, CASE, "wp-f", "undo");
    expect(await row(PASTE_EV)).toEqual(stored);
  });

  it("apply of a new finding conflicts when the id already exists", async () => {
    await stateStore.saveOverview({ ...(await stateStore.loadOverview(CASE)), findings: [draft] });
    await expect(applyWatsonProposal(deps, CASE, "wp-f", "apply")).rejects.toBeInstanceOf(
      WatsonProposalConflict,
    );
    expect(await row(PASTE_EV)).toBeUndefined();
  });

  it("refuses a new finding whose id is not a Watson id or differs from the finding it writes (F14)", async () => {
    await seedChat(
      { ...findingNew(), targetId: "f-model-1" },
      { ...findingNew(), id: "wp-g", targetId: "f-watson-ffff0000" },
    );
    for (const id of ["wp-f", "wp-g"]) {
      await expect(applyWatsonProposal(deps, CASE, id, "apply")).rejects.toThrow(/not a Watson finding id/);
    }
    expect(await findings()).toEqual([]);
    expect(await row(PASTE_EV)).toBeUndefined();
  });

  it("a retry after an apply that failed past the row append owns the row, and undo removes it (F14)", async () => {
    let failSave = true;
    const failing = Object.create(stateStore) as StateStore;
    failing.saveOverview = async (st) => {
      if (failSave) {
        failSave = false;
        throw new Error("disk full");
      }
      return stateStore.saveOverview(st);
    };
    await expect(
      applyWatsonProposal({ ...deps, stateStore: failing }, CASE, "wp-f", "apply"),
    ).rejects.toThrow(/disk full/);
    expect(await row(PASTE_EV)).toBeDefined(); // the row landed, the finding did not
    expect((await proposal()).status).toBe("pending");

    await applyWatsonProposal(deps, CASE, "wp-f", "apply");
    const p = await proposal();
    expect(p.createdEventIds).toEqual([PASTE_EV]);
    expect(p.promotedAt).toBe((await row(PASTE_EV))?.promotedAt);

    await applyWatsonProposal(deps, CASE, "wp-f", "undo");
    expect(await row(PASTE_EV)).toBeUndefined();
    expect(await findings()).toEqual([]);
  });

  describe("finding_update", () => {
    const watsonFinding: Finding = { ...draft, author: "watson", citedPasteLines: undefined };
    const update = (before: Finding): WatsonFindingProposal => ({
      id: "wp-u",
      turnId: "t2",
      kind: "finding_update",
      targetId: FID,
      before,
      after: { ...before, severity: "Critical", title: "Encoded PowerShell ran", relatedEventIds: ["e1"] },
      pasteLineEvents: [],
      status: "pending",
    });

    it("applies over the Watson finding it was made from, and undo restores it", async () => {
      await stateStore.saveOverview({ ...(await stateStore.loadOverview(CASE)), findings: [watsonFinding] });
      await seedChat(update(watsonFinding));
      await applyWatsonProposal(deps, CASE, "wp-u", "apply");
      expect((await findings())[0]).toMatchObject({ severity: "Critical", author: "watson" });
      expect((await row("e1"))?.relatedFindingIds).toEqual([FID]);
      await applyWatsonProposal(deps, CASE, "wp-u", "undo");
      expect((await findings())[0]).toEqual(watsonFinding);
    });

    it("refuses a finding the analyst or synthesis wrote", async () => {
      const synth: Finding = { ...draft, citedPasteLines: undefined };
      await stateStore.saveOverview({ ...(await stateStore.loadOverview(CASE)), findings: [synth] });
      await seedChat(update(synth));
      await expect(applyWatsonProposal(deps, CASE, "wp-u", "apply")).rejects.toBeInstanceOf(
        WatsonProposalConflict,
      );
      expect((await findings())[0]).toEqual(synth);
    });

    it("refuses when the stored finding changed since the proposal", async () => {
      const edited = { ...watsonFinding, description: "edited by the analyst" };
      await stateStore.saveOverview({ ...(await stateStore.loadOverview(CASE)), findings: [edited] });
      await seedChat(update(watsonFinding));
      await expect(applyWatsonProposal(deps, CASE, "wp-u", "apply")).rejects.toBeInstanceOf(
        WatsonProposalConflict,
      );
    });
  });
});
