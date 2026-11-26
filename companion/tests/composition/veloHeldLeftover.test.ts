// #2930: the Velociraptor hunt settle and the external hunt/flow import settle carry the held tagger.
// Their settle sweeps rows earlier imports left marked; a Watson paste's row marked "held" may only be
// graded by the held tagger (a plain one would apply a raise the analyst never approved). Without it
// the sweep offered the row to no tagger, it stayed marked and the case's sweeps backed off. Now it is
// tagged, its raise queued and offered as a held-rows card under its paste. Real stores.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import { heldOfferIdle } from "../../src/analysis/ai/watson/heldOffer.js";
import type { WatsonEventPromoteProposal, WatsonPaste } from "../../src/analysis/ai/watson/types.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { forensicGradePendingIds } from "../../src/analysis/gradeMark.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import { createImportDemote } from "../../src/composition/importDemote.js";
import { createImportTaggers } from "../../src/composition/importTaggers.js";
import { createHuntEvictions, settleHuntCollect } from "../../src/composition/veloHuntSettle.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
import { resetSweepBackoff } from "../../src/routes/importRegrade.js";
import { buildRuntimePipeline, createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { veloServerClients } from "../helpers/serverClientsStub.js";

const CASE = "c1";
const PASTE: WatsonPaste = {
  id: "wf-earlier",
  storedName: "0001_watson-paste.json",
  filename: "events.json",
  bytes: 10,
  lines: 1,
  at: "2026-07-01T11:00:00.000Z",
};

const row = (id: string, description: string, extra: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp: "2026-07-01T11:00:00.000Z",
  description,
  severity: "Info",
  asset: "vault.example.com",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [PASTE.storedName],
  sources: ["SIEM"],
  ...extra,
});
// The bundled rule pack grades `ntdsutil` High: a held row, stamped by the paste whose tagger failed.
const HELD = row("watson-wf-earlier-1", "ntdsutil ifm create full c:\\staging ran on the controller", {
  importBatchId: "batch-paste",
  importedAt: "2026-07-01T11:00:01.000Z",
  gradePending: "held",
});

let root: string;
let cases: CaseStore;
let stateStore: StateStore;
let chatStore: WatsonChatStore;

beforeEach(async () => {
  resetSweepBackoff();
  vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
  vi.spyOn(getServerLogger(), "info").mockImplementation(() => {});
  root = await mkdtemp(join(tmpdir(), "dfir-velo-held-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  await stateStore.save({ ...emptyState(CASE), forensicTimeline: [HELD] });
  chatStore = new WatsonChatStore(cases);
  await chatStore.update(CASE, (c) => ({ ...c, pastes: [...c.pastes, PASTE] }));
});

afterEach(async () => {
  vi.restoreAllMocks();
  await heldOfferIdle(CASE);
  await rm(root, { recursive: true, force: true });
});

const storesOf = (): Partial<AppOptions> => ({
  stateStore,
  superTimelineStore: new SuperTimelineStore(cases),
  tagsStore: new TagsStore(cases),
  taggerStore: new TaggerStore(join(root, "user-tags.yaml")),
  forensicGateControlStore: new ForensicGateControlStore(cases),
  watsonChatStore: chatStore,
});

async function expectOfferedUnderPaste(): Promise<void> {
  await heldOfferIdle(CASE);
  expect(await forensicGradePendingIds(stateStore, CASE)).toEqual([]);
  const chat = await new WatsonChatStore(new CaseStore(root)).load(CASE);
  const cards = chat.proposals.filter((p): p is WatsonEventPromoteProposal => p.kind === "event_promote");
  expect(cards).toHaveLength(1);
  expect(cards[0].pasteId).toBe(PASTE.id);
  expect(cards[0].events.map((e) => [e.id, e.severity])).toEqual([[HELD.id, "High"]]);
  // Not applied: the raise waits for the analyst; the row itself left the forensic timeline as Info.
  const timeline = (await stateStore.load(CASE)).forensicTimeline;
  expect(timeline.find((e) => e.id === HELD.id)).toBeUndefined();
}

describe("#2930 — Velociraptor settles grade a held leftover with the held tagger", () => {
  it("the hunt collect's settle", async () => {
    const lock = new StateLock();
    const runStateExclusive = <T>(caseId: string, fn: () => Promise<T>) => lock.runExclusive(caseId, fn);
    const options = storesOf() as AppOptions;
    const stateBefore = await stateStore.load(CASE);
    // The collect merged one row of its own (graded by the content tagger: not held).
    const own = row("velo-h1-1", "The Time service entered the running state.", {
      sourceScreenshots: ["velo-hunt_H.1.json"],
      sources: ["Velociraptor"],
    });
    await stateStore.save({ ...stateBefore, forensicTimeline: [...stateBefore.forensicTimeline, own] });
    const taggers = createImportTaggers({ options, store: cases, runStateExclusive, logLine: () => {} });
    const result = await settleHuntCollect(
      {
        options,
        ...taggers,
        demoteForensicForCase: createImportDemote({ options, runStateExclusive }).demoteForensicForCase,
        runStateExclusive,
        pushImportCheckpoint: async () => undefined,
      },
      {
        caseId: CASE,
        huntId: "H.1",
        stateBefore,
        importedAny: true,
        lastFile: "velo-hunt_H.1.json",
        bundleName: undefined,
        artifactCount: 1,
        superTimelineAddedCount: 0,
        capDropped: createHuntEvictions(),
      },
    );
    expect(result.error).toBeUndefined();
    await expectOfferedUnderPaste();
  });

  it("the external hunt/flow import's settle, as the app wires it", async () => {
    const client = {
      sourceNamespace: () => "test-server|root",
      async flowMeta() {
        return [
          {
            clientId: "C.1",
            flowId: "F.1",
            state: "FINISHED",
            rows: 1,
            created: 1,
            started: 2,
            active: 3,
            results: ["Windows.NTFS.MFT"],
          },
        ];
      },
      async getFlowInfo() {
        return { artifacts: ["Windows.NTFS.MFT"], hostname: "DESKTOP-01" };
      },
      async collectionResults() {
        const mft = { OSPath: "C:\\notes.txt", Created0x10: "2026-06-01T00:00:00Z", FileName: "notes.txt" };
        return { rows: [mft], total: 1, truncated: false };
      },
      flowGuiUrlFor: () => undefined,
      huntGuiUrlFor: () => undefined,
      async flowUploads() {
        return [];
      },
    };
    const app = createApp(cases, {
      ...storesOf(),
      pipeline: buildRuntimePipeline({
        provider: undefined,
        synthesisProvider: undefined,
        stateStore,
        store: cases,
        imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
      }),
      serverClients: veloServerClients(client),
    });
    const res = await request(app)
      .post(`/cases/${CASE}/velociraptor/import-external`)
      .send({ ref: "https://velo.example/app/index.html?org_id=root#/collected/C.1/F.1" });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    await expectOfferedUnderPaste();
  });
});
