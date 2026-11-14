import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { AiCostStore } from "../../src/analysis/aiCost.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import { heldContentTagger } from "../../src/analysis/ai/watson/heldTagger.js";
import { withPasteIngest } from "../../src/analysis/ai/watson/pasteIngestChat.js";
import { emptyWatsonChat } from "../../src/analysis/ai/watson/types.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { WATSON_MARKER } from "../../src/analysis/timeline/watsonItems.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { createWatsonCaseEvents } from "../../src/composition/watsonCaseEvents.js";
import { createApp } from "../../src/server.js";
import { readWatsonFlowRows } from "../../src/composition/watsonVeloResultsWiring.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// Spec §14: a paste in a known format is parsed and graded, but the content tagger's promotions are
// held as pending Watson proposals; a chat ingest never starts a synthesis (#1599) and never counts
// as a normal import. The bundled rule pack (data/tags.yaml) grades `ntdsutil` High (win_ntds_shadow).

const CASE = "c1";

class Fake implements AIProvider {
  readonly name = "fake";
  readonly model = "fake-model";
  readonly sent: AnalyzeRequest[] = [];
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    return {
      rawText: JSON.stringify({
        message: "I read the paste.",
        workingOn: "",
        learned: "",
        questionUpdates: [],
        newQuestions: [],
        request: null,
        search: null,
        memory: "",
      }),
      usage: { costUSD: 0.01 },
    };
  }
}

// SIEM rows logged at Information level land as Info. Two hosts, so the importer folds nothing.
const siemRow = (host: string, message: string, extra: Record<string, unknown> = {}) => ({
  "@timestamp": "2026-07-01T11:00:00.000Z",
  log_name: "Application",
  computer_name: host,
  event_id: 1000,
  level: "Information",
  message,
  ...extra,
});

const SIEM = JSON.stringify([
  siemRow("vault.example.com", "ntdsutil ifm create full c:\\staging ran on the controller"),
  siemRow("desk.example.com", "The Windows Update service entered the running state."),
]);

let root: string | undefined;
const savedEnv = { ...process.env };
afterEach(async () => {
  process.env = { ...savedEnv };
  if (root) await rm(root, { recursive: true, force: true });
  root = undefined;
});

async function harness() {
  root = await mkdtemp(join(tmpdir(), "dfir-watson-ingest-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await stateStore.save(emptyState(CASE));
  const aiControlStore = new AiControlStore(store);
  await aiControlStore.save(CASE, { enabled: true, lastAnalyzedSeq: 0 });
  const stateLock = new StateLock();
  const fake = new Fake();
  const aiCostStore = new AiCostStore(store);
  const pipeline = new AnalysisPipeline({
    provider: fake,
    synthesisProvider: fake,
    stateStore,
    stateLock,
    aiCostStore,
    anonStore: new AnonControlStore(store),
    retries: 0,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
  const superTimelineStore = new SuperTimelineStore(store);
  const chatStore = new WatsonChatStore(store);
  const onImportMeta = vi.fn();
  // The real case-event wiring (composition/appWiring.ts), with the app's own reaction scheduler.
  const tagsStore = new TagsStore(store);
  const events = createWatsonCaseEvents(chatStore, tagsStore);
  const reactions: { note?: ReturnType<typeof vi.fn> } = {};
  const synthesize = vi.spyOn(pipeline, "synthesize");
  const analyzeCsv = vi.spyOn(pipeline, "analyzeCsv");
  const appendImport = vi.spyOn(store, "appendImport");
  const app = createApp(store, {
    importLock: new ImportLock(),
    stateStore,
    stateLock,
    pipeline,
    aiCostStore,
    synthMetaStore: new SynthMetaStore(store),
    superTimelineStore,
    tagsStore,
    taggerStore: new TaggerStore(join(root, "user-tags.yaml")),
    forensicGateControlStore: new ForensicGateControlStore(store),
    activityLogStore: new ActivityLogStore(store),
    watsonChatStore: chatStore,
    watsonProvider: () => fake,
    onImportMeta: (caseId) => {
      onImportMeta(caseId);
      events.note(caseId, { kind: "import", text: "An import finished" });
    },
    onTags: (caseId) => events.tagsChanged(caseId),
    onNotebook: (caseId) => events.note(caseId, { kind: "notebook", text: "Analyst edited the notebook" }),
    onWatsonReactorReady: (reactor) => {
      reactions.note = vi.spyOn(reactor, "note") as unknown as ReturnType<typeof vi.fn>;
      events.attach(reactor);
    },
  });
  return {
    app,
    stateStore,
    chatStore,
    fake,
    onImportMeta,
    synthesize,
    analyzeCsv,
    superTimelineStore,
    loggedRows: () => appendImport.mock.calls.at(-1)?.[1].rows,
    reactions,
  };
}

const mentions = (events: ForensicEvent[], text: string) =>
  events.filter((e) => JSON.stringify(e).includes(text));

async function paste(app: Express.Application, text: string, filename: string) {
  return request(app as never)
    .post(`/cases/${CASE}/watson/paste`)
    .send({ text, filename });
}

describe("Watson paste ingest", () => {
  it("reads a Watson collection's rows (as readWatsonFlowRows writes them) with the Velociraptor importer", async () => {
    const h = await harness();
    const client = {
      getFlowInfo: async () => ({
        artifacts: ["Custom.Collect.Companion.process_listing/Pivot0"],
        hostname: "",
      }),
      collectionResults: async () => ({
        rows: [
          {
            Pid: 4242,
            Name: "rundll32.exe",
            CommandLine: "rundll32.exe comsvcs.dll MiniDump 612 out.dmp full",
          },
          { Pid: 612, Name: "lsass.exe", CommandLine: "C:\\Windows\\system32\\lsass.exe" },
        ],
        total: 2,
        truncated: false,
      }),
    };
    const proposal = {
      id: "wp-coll",
      turnId: "t1",
      kind: "velo_launch" as const,
      status: "applied" as const,
      targetId: "fp1",
      mode: "collection" as const,
      hostname: "web01.example.com",
      title: "Process listing",
      vql: "SELECT * FROM pslist()",
      fingerprint: "fp1",
      fingerprints: ["fp1"],
      launched: { flowId: "F.SAMPLE", clientId: "C.webserver1", at: "2026-11-14T10:00:00Z", by: "Dana" },
    };
    const rows = await readWatsonFlowRows(client, proposal);
    const res = await paste(h.app as never, rows.text, "velo-flow_F.SAMPLE.json");
    expect(res.status).toBe(200);
    const parsed = (await h.chatStore.load(CASE)).pastes[0].parsed;
    expect(parsed).toMatchObject({ kind: "velociraptor" });
    expect(parsed && "rows" in parsed ? parsed.rows : 0).toBeGreaterThan(0);
    expect(h.synthesize).not.toHaveBeenCalled();
  });

  it("parses a known format, holds the tagger's promotion as a proposal, and applies/undoes it", async () => {
    const h = await harness();
    const res = await paste(h.app as never, SIEM, "events.json");
    expect(res.status).toBe(200);

    // The tagger's High row is NOT in the forensic timeline: it stayed Info and demote moved it.
    const forensic = (await h.stateStore.load(CASE)).forensicTimeline;
    expect(mentions(forensic, "ntdsutil")).toHaveLength(0);
    const superRows: ForensicEvent[] = [];
    for await (const b of h.superTimelineStore.eventBatches(CASE)) superRows.push(...b);
    expect(mentions(superRows, "ntdsutil")).toHaveLength(1);

    const chat = await h.chatStore.load(CASE);
    const held = chat.proposals.filter((p) => p.kind === "event_promote");
    expect(held).toHaveLength(1);
    expect(held[0].status).toBe("pending");
    expect(held[0].events).toHaveLength(1);
    expect(held[0].events[0].severity).toBe("High");
    expect(held[0].events[0].provenance).toContain(WATSON_MARKER);
    expect(chat.pastes[0].parsed).toMatchObject({ kind: "siem", rows: 2, held: 1 });
    const system = chat.turns.find((t) => t.role === "system");
    expect(system?.text).toBe(
      "Parsed 2 rows from events.json (siem). 1 rows the tagger graded above Info wait for your approval.",
    );
    expect(system?.proposalIds).toEqual([held[0].id]);
    // The system turn comes before the round's analyst turn.
    const roles = chat.turns.map((t) => t.role);
    expect(roles.indexOf("system")).toBeLessThan(roles.indexOf("analyst"));
    // The round's prompt carries the system turn.
    expect(JSON.stringify(h.fake.sent[0])).toContain("Parsed 2 rows from events.json (siem)");

    // The import log records the parsed row count, not 0.
    expect(h.loggedRows()).toBe(2);

    // Neither a synthesis nor a normal-import broadcast.
    await new Promise((r) => setTimeout(r, 50));
    expect(h.synthesize).not.toHaveBeenCalled();
    expect(h.onImportMeta).not.toHaveBeenCalled();

    const applied = await request(h.app).post(`/cases/${CASE}/watson/proposals/${held[0].id}/apply`);
    expect(applied.status).toBe(200);
    const after = mentions((await h.stateStore.load(CASE)).forensicTimeline, "ntdsutil");
    expect(after).toHaveLength(1);
    expect(after[0].severity).toBe("High");
    expect(after[0].promotedAt).toBeTruthy();
    expect(after[0].provenance).toContain(WATSON_MARKER);

    const undone = await request(h.app).post(`/cases/${CASE}/watson/proposals/${held[0].id}/undo`);
    expect(undone.status).toBe(200);
    expect(mentions((await h.stateStore.load(CASE)).forensicTimeline, "ntdsutil")).toHaveLength(0);
  });

  it("a paste ingest and a proposal apply schedule no Watson reaction (spec §4.6)", async () => {
    const h = await harness();
    expect(h.reactions.note, "createApp built and attached the shared reactor").toBeDefined();
    await paste(h.app as never, SIEM, "events.json");
    const pid = (await h.chatStore.load(CASE)).proposals.find((p) => p.kind === "event_promote")!.id;
    expect((await request(h.app).post(`/cases/${CASE}/watson/proposals/${pid}/apply`)).status).toBe(200);
    await new Promise((r) => setTimeout(r, 50));
    expect(h.reactions.note).not.toHaveBeenCalled();
    expect((await h.chatStore.load(CASE)).pendingCaseEvents).toEqual([]);
    expect(h.synthesize).not.toHaveBeenCalled();
  });

  it("undo answers 409 while a Watson finding cites the promoted row", async () => {
    const h = await harness();
    await paste(h.app as never, SIEM, "events.json");
    const pid = (await h.chatStore.load(CASE)).proposals.find((p) => p.kind === "event_promote")!.id;
    await request(h.app).post(`/cases/${CASE}/watson/proposals/${pid}/apply`);
    const id = mentions((await h.stateStore.load(CASE)).forensicTimeline, "ntdsutil")[0].id;
    const finding: Finding = {
      id: "f-watson-0a1b2c3d",
      author: "watson",
      severity: "High",
      title: "Directory database staged",
      description: "ntdsutil staged the directory database.",
      relatedIocs: [],
      sourceScreenshots: [],
      mitreTechniques: [],
      relatedEventIds: [id],
      firstSeen: "2026-07-01T11:00:00Z",
      lastUpdated: "2026-07-01T11:00:00Z",
      status: "open",
    };
    const overview = await h.stateStore.loadOverview(CASE);
    await h.stateStore.saveOverview({ ...overview, findings: [finding] });
    const res = await request(h.app).post(`/cases/${CASE}/watson/proposals/${pid}/undo`);
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/undo the finding that cites it first/);
  });

  it("proposes a row a lab cap lowers at the capped grade, not the tagger's", async () => {
    process.env.DFIR_LAB_SETUP_PATHS = "\\labdrop\\";
    const h = await harness();
    const text = JSON.stringify([
      siemRow("vault.example.com", "staged CommandLineEventConsumer setup for the lab", {
        event_data: { Image: "C:\\labdrop\\wmisetup.exe" },
      }),
      siemRow("desk.example.com", "The Windows Update service entered the running state."),
    ]);
    await paste(h.app as never, text, "lab.json");
    const held = (await h.chatStore.load(CASE)).proposals.filter((p) => p.kind === "event_promote");
    expect(held).toHaveLength(1);
    expect(held[0].events[0].severity).toBe("Medium");
    // The lab-cap record survives apply, so a later lift can restore the tagger's grade.
    await request(h.app).post(`/cases/${CASE}/watson/proposals/${held[0].id}/apply`);
    const row = mentions(
      (await h.stateStore.load(CASE)).forensicTimeline,
      "CommandLineEventConsumer",
    )[0] as ForensicEvent & { labSetup?: { cappedFrom?: string } };
    expect(row.severity).toBe("Medium");
    expect(row.labSetup?.cappedFrom).toBe("High");
  });

  it("leaves a generic CSV as searchable text and never calls the AI to extract it", async () => {
    const h = await harness();
    const csv = "when,who,what\n2026-07-01,clerk,opened the ledger\n2026-07-02,keeper,closed the ledger\n";
    const res = await paste(h.app as never, csv, "notes.csv");
    expect(res.status).toBe(200);
    expect(h.analyzeCsv).not.toHaveBeenCalled();
    expect(h.fake.sent).toHaveLength(1); // the round only
    const chat = await h.chatStore.load(CASE);
    expect(chat.pastes[0].parsed).toMatchObject({ kind: "text" });
    expect(chat.turns.some((t) => t.role === "system")).toBe(false);
    expect(chat.proposals).toHaveLength(0);
    expect(h.loggedRows()).toBe(0);
  });
});

describe("held tagger and the chat it builds", () => {
  const ev = (id: string, severity: ForensicEvent["severity"]): ForensicEvent => ({
    id,
    timestamp: "2026-07-01T11:00:00.000Z",
    description: "CommandLineEventConsumer registered on vault.example.com",
    severity,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  });

  it("holds only rows the tagger raises out of Info, and changes no grade", async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-watson-held-"));
    const store = new CaseStore(root);
    await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
    const tagsStore = new TagsStore(store);
    const held = heldContentTagger({ taggerStore: new TaggerStore(join(root, "user-tags.yaml")), tagsStore });
    const info = ev("e-info", "Info");
    const low = ev("e-low", "Low");
    await held.tag(CASE, [info, low]);
    expect(held.held().map((e) => [e.id, e.severity])).toEqual([["e-info", "High"]]);
    expect(info.severity).toBe("Info"); // the input is not mutated
    expect(held.offered()).toHaveLength(2);
    // Tags are still written for both rows.
    const tags = await tagsStore.load(CASE);
    expect(new Set(tags.map((t) => t.targetId))).toEqual(new Set(["e-info", "e-low"]));
  });

  it("splits held rows 25 per proposal and states the cut past 200", () => {
    const paste = { id: "wf-9", storedName: "0009_x.json", filename: "x.json", bytes: 1, lines: 1, at: "t" };
    const many = Array.from({ length: 230 }, (_, i) => ev(`e${i}`, "High"));
    const chat = withPasteIngest(emptyWatsonChat(), paste, { kind: "siem", rows: 500, held: many });
    expect(chat.proposals).toHaveLength(8);
    expect(chat.proposals.every((p) => p.kind === "event_promote" && p.events.length === 25)).toBe(true);
    expect(chat.turns[0].text).toContain("230 rows the tagger graded above Info");
    expect(chat.turns[0].text).toContain(
      "Only the first 200 are proposed; the other 30 stay in the super-timeline.",
    );
    expect(chat.pastes[0].parsed).toEqual({ kind: "siem", rows: 500, held: 230 });
  });
});
