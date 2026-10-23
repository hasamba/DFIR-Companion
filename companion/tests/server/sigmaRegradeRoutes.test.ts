// Re-grade an imported case with the current Sigma rules (#2206): the preview and apply routes,
// through the real app, the real pipeline merge, the real super-timeline and the real demote.
// A CloudTrail file is imported under one rule set; the rule that graded it is then switched off.
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp, readdir, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ImportUndoStore } from "../../src/analysis/importUndo.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { createApp } from "../../src/server.js";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";
import { sigmaTokensOf, splitSigmaOverlay } from "../../src/analysis/sigmaRegrade.js";
import type { SigmaRuleSet } from "../../src/analysis/sigmaRuleSet.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { pollFor } from "../helpers/poll.js";
import { bundledSigmaDir, ruleFiles } from "../../src/analysis/sigmaBundledRules.js";
import { SigmaRuleStore } from "../../src/analysis/sigmaRuleStore.js";
import { createZip } from "../../src/analysis/zipArchive.js";
import { sigmaGradingsInCase } from "../../src/reports/detectionRules.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import {
  ImportMemoryRefusedError,
  type ImportAdmission,
  type ImportAdmissionHint,
} from "../../src/analysis/importMemoryGuard.js";

const ct = (i: number, o: Record<string, unknown>) => ({
  eventVersion: "1.08",
  eventTime: `2026-03-01T10:00:0${i}Z`,
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.7",
  userAgent: "aws-cli/2.15.0",
  userIdentity: {
    type: "IAMUser",
    userName: "alice",
    accountId: "111122223333",
    arn: "arn:aws:iam::111122223333:user/alice",
  },
  recipientAccountId: "111122223333",
  readOnly: false,
  eventID: `id-${i}`,
  ...o,
});

const TEXT = JSON.stringify({
  Records: [
    ct(1, { eventSource: "securityhub.amazonaws.com", eventName: "BatchUpdateFindings" }),
    ct(2, { eventSource: "cloudtrail.amazonaws.com", eventName: "StopLogging" }),
  ],
});

const { set: SET_ON } = loadBundledSigmaRuleSet();
const graded = parseCloudTrail(TEXT, { sigma: createSigmaImportGrader(SET_ON).snapshot() }).events.find((e) =>
  /BatchUpdateFindings/.test(e.description),
)!;
const RULE_ID = splitSigmaOverlay(graded.description, graded.message).ruleIds[0];
const { set: SET_OFF } = loadBundledSigmaRuleSet({ disabled: new Map([[RULE_ID, "noisy here"]]) });
/** The importer's own grade for the record, with no Sigma rule. */
const BASE = parseCloudTrail(TEXT).events.find((e) => /BatchUpdateFindings/.test(e.description))!;

let rules: SigmaRuleSet;
let sigmaOn: boolean;
let cases: CaseStore;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let meta: SynthMetaStore;
let synthesize: { mock: { calls: unknown[] } };

function build(extra: Record<string, unknown> = {}) {
  const stateLock = new StateLock();
  const pipeline = new AnalysisPipeline({
    stateStore,
    stateLock,
    sigmaGrader: createSigmaImportGrader(() => rules, { enabled: () => sigmaOn }),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  synthesize = vi.spyOn(pipeline, "synthesize");
  return createApp(cases, {
    pipeline,
    stateStore,
    stateLock,
    superTimelineStore: superStore,
    importMetaStore: new ImportMetaStore(cases),
    forensicGateControlStore: new ForensicGateControlStore(cases),
    activityLogStore: new ActivityLogStore(cases),
    synthMetaStore: meta,
    ...extra,
  });
}

const target = (rows: ForensicEvent[]) => rows.find((e) => /BatchUpdateFindings/.test(e.description));

async function importTrail(app: ReturnType<typeof createApp>): Promise<void> {
  const res = await request(app)
    .post("/cases/c1/import-aws")
    .send({ filename: "cloudtrail.json", text: TEXT });
  expect(res.status).toBe(202);
  await pollFor("the CloudTrail import to settle", async () => {
    const m = await new ImportMetaStore(cases).load("c1");
    return m.lastImportKind === "aws" ? m : undefined;
  });
}

/** Entra sign-ins: no importer rule version, so a Sigma-off import leaves `ruleVersions` unset. */
const SIGN_INS = JSON.stringify({
  value: [
    {
      id: "s-1",
      createdDateTime: "2026-03-01T10:00:00Z",
      userPrincipalName: "alice@example.test",
      appDisplayName: "Azure Portal",
      ipAddress: "198.51.100.7",
      clientAppUsed: "Browser",
      userAgent: "azurehound/v2.1.0",
      status: { errorCode: 0 },
    },
  ],
});

async function importSignIns(app: ReturnType<typeof createApp>): Promise<void> {
  const res = await request(app)
    .post("/cases/c1/import-m365")
    .send({ filename: "signins.json", text: SIGN_INS });
  expect(res.status).toBe(202);
  await pollFor("the sign-in import to settle", async () => {
    const m = await new ImportMetaStore(cases).load("c1");
    return m.lastImportKind === "m365" ? m : undefined;
  });
}

/** A case gate above the importer's own grade for the record (Info or Low): Medium. */
const gateAboveBase = async () => {
  expect(["Info", "Low"]).toContain(BASE.severity);
  await new ForensicGateControlStore(cases).set("c1", { minSeverity: "Medium" });
};

const superRow = async (id: string) => superStore.get("c1", id);

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-sigma-regrade-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  superStore = new SuperTimelineStore(cases);
  meta = new SynthMetaStore(cases);
  // The case has conclusions from an earlier synthesis, so there is something to be out of date.
  await meta.record("c1", null as never, "2026-03-01T12:00:00.000Z");
  rules = SET_ON;
  sigmaOn = true;
});

describe("GET /cases/:id/sigma/regrade — the preview (#2206)", () => {
  it("says the case is current when the rules are unchanged", async () => {
    const app = build();
    await importTrail(app);
    const res = await request(app).get("/cases/c1/sigma/regrade");
    expect(res.status).toBe(200);
    expect(res.body.current).toBe(true);
    expect(res.body.counts).toMatchObject({ raised: 0, lowered: 0, changed: 0, tokenOnly: 0 });
  });

  it("counts what a re-grade would change and writes nothing", async () => {
    const app = build();
    await importTrail(app);
    const before = await stateStore.load("c1");
    const row = target(before.forensicTimeline)!;
    const superBefore = await superRow(row.id);
    rules = SET_OFF;
    const res = await request(app).get("/cases/c1/sigma/regrade");
    expect(res.status).toBe(200);
    expect(res.body.current).toBe(false);
    expect(res.body.counts.lowered).toBe(1);
    expect(res.body.files[0]).toMatchObject({ importer: "aws-cloudtrail", status: "other" });
    const after = await stateStore.load("c1");
    expect(after.forensicTimeline).toEqual(before.forensicTimeline);
    expect(await superRow(row.id)).toEqual(superBefore);
    expect((await meta.load("c1")).outOfDate ?? null).toBeNull();
  });
});

describe("POST /cases/:id/sigma/regrade — the apply (#2206)", () => {
  it("lowers the row in both timelines, demotes it when it falls below the gate, and starts no synthesis", async () => {
    await gateAboveBase();
    const app = build();
    await importTrail(app);
    const row = target((await stateStore.load("c1")).forensicTimeline)!;
    expect(row.severity).toBe("High");
    rules = SET_OFF;
    const res = await request(app).post("/cases/c1/sigma/regrade").send({});
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ applied: true, counts: { lowered: 1, raised: 0 } });

    const sup = (await superRow(row.id))!;
    expect(sup.severity).toBe(BASE.severity);
    expect(sup.description).not.toMatch(/^Sigma: /);
    expect(sigmaTokensOf(sup)).toEqual([createSigmaImportGrader(SET_OFF).snapshot()!.token]);
    // The importer's own grade is below the case's gate, so the lowered row leaves the forensic
    // timeline; its super-timeline copy (above) already carries the new grade.
    expect(target((await stateStore.load("c1")).forensicTimeline)).toBeUndefined();
    expect(res.body.demoted).toBe(1);
    expect(res.body.counts.leavesForensic).toBe(1);
    expect(synthesize).not.toHaveBeenCalled();
    expect((await meta.load("c1")).outOfDate?.reason).toBe("Sigma re-grade");
  });

  it("keeps an analyst-promoted row with its promotedAt, at the new grade, and adds promotedAt to nothing", async () => {
    const app = build();
    await importTrail(app);
    const state = await stateStore.load("c1");
    const row = target(state.forensicTimeline)!;
    await stateStore.save({
      ...state,
      forensicTimeline: state.forensicTimeline.map((e) =>
        e.id === row.id ? { ...e, promotedAt: "2026-03-02T00:00:00.000Z" } : e,
      ),
    });
    rules = SET_OFF;
    const res = await request(app).post("/cases/c1/sigma/regrade").send({});
    expect(res.status).toBe(200);
    const after = await stateStore.load("c1");
    const kept = target(after.forensicTimeline)!;
    expect(kept.promotedAt).toBe("2026-03-02T00:00:00.000Z");
    expect(kept.severity).toBe(BASE.severity);
    expect(kept.description).not.toMatch(/^Sigma: /);
    expect(kept.message ?? "").not.toMatch(/Sigma rule: /);
    expect(after.forensicTimeline.filter((e) => e.promotedAt).map((e) => e.id)).toEqual([row.id]);
    expect((await superRow(row.id))!.severity).toBe(BASE.severity);
  });

  it("raises the row again when the rule is switched back on, without promoting it", async () => {
    rules = SET_OFF;
    await gateAboveBase();
    const app = build();
    await importTrail(app);
    expect(target((await stateStore.load("c1")).forensicTimeline)).toBeUndefined();
    const sup = (await superStore.query("c1", {})).events.find((e) =>
      /BatchUpdateFindings/.test(e.description),
    )!;
    rules = SET_ON;
    const res = await request(app).post("/cases/c1/sigma/regrade").send({});
    expect(res.status).toBe(200);
    expect(res.body.counts).toMatchObject({ raised: 1, entersForensic: 1 });
    const row = target((await stateStore.load("c1")).forensicTimeline)!;
    expect(row.id).toBe(sup.id);
    expect(row.severity).toBe("High");
    expect(row.description).toMatch(/^Sigma: /);
    expect(row.promotedAt).toBeUndefined();
    expect(row.provenance ?? []).not.toContain("[promoted]");
  });

  it("stamps the grading on every row of an import made with Sigma off, in both timelines", async () => {
    sigmaOn = false;
    const app = build();
    await importSignIns(app);
    const m365 = (rows: ForensicEvent[]) => rows.filter((e) => e.canonical?.producer?.importer === "m365");
    const before = m365((await superStore.query("c1", {})).events);
    expect(before.length).toBeGreaterThan(0);
    expect(before.every((e) => !e.canonical!.producer.ruleVersions)).toBe(true);
    sigmaOn = true;
    const token = createSigmaImportGrader(SET_ON).snapshot()!.token;
    const res = await request(app).post("/cases/c1/sigma/regrade").send({});
    expect(res.status).toBe(200);
    expect(res.body.counts.raised).toBeGreaterThan(0);

    const forensic = m365((await stateStore.load("c1")).forensicTimeline);
    expect(forensic.length).toBeGreaterThan(0);
    for (const e of forensic) expect(sigmaTokensOf(e)).toEqual([token]);
    for (const e of before) expect(sigmaTokensOf((await superRow(e.id))!)).toEqual([token]);
    expect(sigmaGradingsInCase(forensic).map((g) => g.release)).toEqual([SET_ON.release]);

    const again = await request(app).get("/cases/c1/sigma/regrade");
    expect(again.body.counts).toMatchObject({ changed: 0, tokenOnly: 0 });
    const file = again.body.files.find((f: { file: string }) => /signins\.json$/.test(f.file));
    expect(file).toMatchObject({ importer: "m365", status: "current" });
  });

  it("moves nothing when the rules are unchanged", async () => {
    const app = build();
    await importTrail(app);
    const before = await stateStore.load("c1");
    const res = await request(app).post("/cases/c1/sigma/regrade").send({});
    expect(res.status).toBe(200);
    expect(res.body.counts).toMatchObject({ changed: 0, tokenOnly: 0 });
    expect((await stateStore.load("c1")).forensicTimeline).toEqual(before.forensicTimeline);
    expect((await meta.load("c1")).outOfDate ?? null).toBeNull();
  });

  it("is refused for a closed case", async () => {
    const app = build();
    await cases.updateCaseMeta("c1", { status: "closed" });
    const res = await request(app).post("/cases/c1/sigma/regrade").send({});
    expect(res.status).toBe(423);
  });

  it("is refused in the public demo", async () => {
    const app = build({ demoMode: true });
    const res = await request(app).post("/cases/c1/sigma/regrade").send({});
    expect(res.status).toBe(403);
  });
});

// #2227: the apply re-parses every stored import file, so it is single-flight per case and sized
// for the memory guard like every other import section.
describe("POST /cases/:id/sigma/regrade — admission (#2227)", () => {
  const storedBytes = async () => {
    const dir = cases.importsDir("c1");
    let total = 0;
    for (const f of await readdir(dir)) total += (await stat(join(dir, f))).size;
    return total;
  };

  it("a second re-grade of the same case is refused with 409 while one runs, and the first still applies", async () => {
    let gate: Promise<void> | undefined;
    let entered: () => void = () => {};
    const inAdmission = new Promise<void>((r) => (entered = r));
    let open: () => void = () => {};
    const admission: ImportAdmission = {
      admit: async () => {
        if (gate) {
          entered();
          await gate;
        }
        return () => {};
      },
    };
    const app = build({ importLock: new ImportLock(admission) });
    await importTrail(app);
    rules = SET_OFF;
    gate = new Promise<void>((r) => (open = r));

    const first = request(app)
      .post("/cases/c1/sigma/regrade")
      .send({})
      .then((r) => r);
    await inAdmission;
    const second = await request(app).post("/cases/c1/sigma/regrade").send({});
    expect(second.status).toBe(409);
    expect(second.body.error).toMatch(/already running/);

    gate = undefined;
    open();
    const done = await first;
    expect(done.status).toBe(200);
    expect(done.body.applied).toBe(true);
    expect(done.body.counts.lowered).toBe(1);

    const third = await request(app).post("/cases/c1/sigma/regrade").send({});
    expect(third.status).toBe(200);
  });

  it("is sized for the memory guard from the stored import files, and a refusal changes nothing", async () => {
    const hints: ImportAdmissionHint[] = [];
    let refuse = false;
    const admission: ImportAdmission = {
      admit: async (_caseId, hint) => {
        if (hint) hints.push(hint);
        if (refuse) throw new ImportMemoryRefusedError(`refused. Then ${hint?.wording?.retry ?? "-"}.`);
        return () => {};
      },
    };
    const app = build({ importLock: new ImportLock(admission) });
    await importTrail(app);
    rules = SET_OFF;
    const forensicBefore = (await stateStore.load("c1")).forensicTimeline;
    const row = target(forensicBefore)!;
    const superBefore = await superRow(row.id);
    const imported = hints.length;
    refuse = true;

    const refused = await request(app).post("/cases/c1/sigma/regrade").send({});
    expect(refused.status).toBe(503);
    expect(hints.length).toBe(imported + 1);
    const hint = hints.at(-1)!;
    expect(hint.incomingBytes).toBe(await storedBytes());
    expect(hint.incomingBytes).toBeGreaterThan(0);
    expect(hint.wording?.retry).toMatch(/re-grade/);
    expect(refused.body.error).toContain(hint.wording!.retry);
    expect((await stateStore.load("c1")).forensicTimeline).toEqual(forensicBefore);
    expect(await superRow(row.id)).toEqual(superBefore);

    refuse = false;
    const next = await request(app).post("/cases/c1/sigma/regrade").send({});
    expect(next.status).toBe(200);
    expect(next.body.applied).toBe(true);
  });
});

// #2220: Undo of a re-grade puts BOTH timelines back; Redo re-grades both again.
describe("Undo / Redo of a Sigma re-grade (#2220)", () => {
  /** The fields a re-grade rewrites on a super-timeline copy. */
  const grade = (e: ForensicEvent | null | undefined) =>
    e && { severity: e.severity, description: e.description, message: e.message, tokens: sigmaTokensOf(e) };
  const findSuper = async () =>
    (await superStore.query("c1", {})).events.find((e) => /BatchUpdateFindings/.test(e.description))!;
  let superNotices: string[];
  const buildWithUndo = () => {
    superNotices = [];
    return build({
      importUndoStore: new ImportUndoStore(cases),
      onSuperTimeline: (caseId: string) => superNotices.push(caseId),
    });
  };
  const step = async (app: ReturnType<typeof createApp>, which: "undo" | "redo") => {
    superNotices.length = 0;
    const res = await request(app).post(`/cases/c1/import/${which}`).send({});
    expect(res.status).toBe(200);
    expect(superNotices).toContain("c1");
  };

  it("a lowered and demoted row comes back to forensic AND its super copy gets its old grade", async () => {
    await gateAboveBase();
    const app = buildWithUndo();
    await importTrail(app);
    const row = target((await stateStore.load("c1")).forensicTimeline)!;
    const superBefore = grade(await superRow(row.id));
    expect(superBefore!.severity).toBe("High");
    rules = SET_OFF;
    expect((await request(app).post("/cases/c1/sigma/regrade").send({})).body.demoted).toBe(1);
    const superAfter = grade(await superRow(row.id));
    expect(superAfter!.severity).toBe(BASE.severity);

    await step(app, "undo");
    expect(target((await stateStore.load("c1")).forensicTimeline)?.severity).toBe("High");
    expect(grade(await superRow(row.id))).toEqual(superBefore);

    await step(app, "redo");
    expect(target((await stateStore.load("c1")).forensicTimeline)).toBeUndefined();
    expect(grade(await superRow(row.id))).toEqual(superAfter);
  });

  it("a raised row leaves forensic again AND its super copy drops back to its old grade", async () => {
    rules = SET_OFF;
    await gateAboveBase();
    const app = buildWithUndo();
    await importTrail(app);
    const superBefore = grade(await findSuper());
    expect(superBefore!.severity).toBe(BASE.severity);
    rules = SET_ON;
    expect((await request(app).post("/cases/c1/sigma/regrade").send({})).body.counts.entersForensic).toBe(1);
    const superAfter = grade(await findSuper());
    expect(superAfter!.severity).toBe("High");

    await step(app, "undo");
    expect(target((await stateStore.load("c1")).forensicTimeline)).toBeUndefined();
    expect(grade(await findSuper())).toEqual(superBefore);

    await step(app, "redo");
    expect(target((await stateStore.load("c1")).forensicTimeline)?.severity).toBe("High");
    expect(grade(await findSuper())).toEqual(superAfter);
  });
});

// A re-grade that fails part-way puts BOTH timelines back before it answers 500, so a retry plans
// from the original rows and its Undo restores the original grade.
describe("a failed Sigma re-grade apply rolls back both timelines (#2206)", () => {
  const grade = (e: ForensicEvent | null | undefined) =>
    e && { severity: e.severity, description: e.description, message: e.message, tokens: sigmaTokensOf(e) };
  const failures: Record<string, () => void> = {
    "after the super-timeline rewrite": () =>
      void vi
        .spyOn(AnalysisPipeline.prototype, "mergeSigmaRegrade")
        .mockRejectedValueOnce(new Error("injected merge failure")),
    "after the forensic merge": () =>
      void vi
        .spyOn(stateStore, "forensicRowsById")
        .mockRejectedValueOnce(new Error("injected cleanup failure")),
    "after the cleanup": () =>
      void vi
        .spyOn(stateStore, "deleteForensicRows")
        .mockRejectedValueOnce(new Error("injected demote failure")),
  };

  for (const [where, inject] of Object.entries(failures)) {
    it(`${where}: both timelines equal their pre-apply state; a retry then Undo restores the originals`, async () => {
      await gateAboveBase();
      const app = build({ importUndoStore: new ImportUndoStore(cases) });
      await importTrail(app);
      const forensicBefore = (await stateStore.load("c1")).forensicTimeline;
      const row = target(forensicBefore)!;
      const superBefore = await superRow(row.id);
      expect(grade(superBefore)!.severity).toBe("High");
      rules = SET_OFF;

      inject();
      const failed = await request(app).post("/cases/c1/sigma/regrade").send({});
      vi.restoreAllMocks();
      expect(failed.status).toBe(500);
      expect((await stateStore.load("c1")).forensicTimeline).toEqual(forensicBefore);
      expect(await superRow(row.id)).toEqual(superBefore);

      const retry = await request(app).post("/cases/c1/sigma/regrade").send({});
      expect(retry.status).toBe(200);
      expect(retry.body.counts).toMatchObject({ lowered: 1 });
      expect(grade(await superRow(row.id))!.severity).toBe(BASE.severity);

      expect((await request(app).post("/cases/c1/import/undo").send({})).status).toBe(200);
      expect(target((await stateStore.load("c1")).forensicTimeline)).toEqual(row);
      expect(grade(await superRow(row.id))).toEqual(grade(superBefore));
    });
  }
});

// #2209: measure a staged (not installed) release against the case before installing it.
describe("GET /cases/:id/sigma/regrade?release=<token> — measure a staged release (#2209)", () => {
  /** A staged release without the rule that graded the record. */
  async function stagedWithout(ruleId: string): Promise<{ store: SigmaRuleStore; token: string }> {
    const dir = bundledSigmaDir() as string;
    const files = ruleFiles(dir).files.filter((f) => !f.text.includes(`id: ${ruleId}`));
    const root = await mkdtemp(join(tmpdir(), "dfir-sigma-staged-"));
    const store = new SigmaRuleStore(root, dir, {});
    await store.init();
    const zip = createZip(files.map((f) => ({ path: f.path, data: Buffer.from(f.text) })));
    const p = await store.preview(zip, { source: "file", fileName: "next.zip", verified: false });
    return { store, token: p.token };
  }

  it("grades the case with the staged release and writes nothing", async () => {
    const { store, token } = await stagedWithout(RULE_ID);
    const app = build({ sigmaRuleStore: store });
    await importTrail(app);
    const before = await stateStore.load("c1");
    const row = target(before.forensicTimeline)!;
    const superBefore = await superRow(row.id);
    const active = await request(app).get("/cases/c1/sigma/regrade");
    expect(active.body.counts.lowered).toBe(0);
    const res = await request(app).get(`/cases/c1/sigma/regrade?release=${encodeURIComponent(token)}`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ staged: true, release: "file next.zip", current: false });
    expect(res.body.counts.lowered).toBe(1);
    expect((await stateStore.load("c1")).forensicTimeline).toEqual(before.forensicTimeline);
    expect(await superRow(row.id)).toEqual(superBefore);
    expect((await meta.load("c1")).outOfDate ?? null).toBeNull();
    expect(store.active().id).toBe("bundled");
  });

  it("refuses an unknown token with the install wording", async () => {
    const { store } = await stagedWithout(RULE_ID);
    const app = build({ sigmaRuleStore: store });
    const res = await request(app).get("/cases/c1/sigma/regrade?release=nope");
    expect(res.status).toBe(404);
    expect(res.body.error).toBe("that preview is gone — preview the release again");
  });

  it("refuses a stale preview", async () => {
    const { store, token } = await stagedWithout(RULE_ID);
    const app = build({ sigmaRuleStore: store });
    const clock = vi.spyOn(Date, "now").mockReturnValue(Date.now() + 61 * 60 * 1000);
    try {
      const res = await request(app).get(`/cases/c1/sigma/regrade?release=${encodeURIComponent(token)}`);
      expect(res.status).toBe(409);
    } finally {
      clock.mockRestore();
    }
  });

  it("answers 501 without a rule store and 404 for an unknown case", async () => {
    expect((await request(build()).get("/cases/c1/sigma/regrade?release=t")).status).toBe(501);
    const { store, token } = await stagedWithout(RULE_ID);
    const app = build({ sigmaRuleStore: store });
    expect((await request(app).get(`/cases/nope/sigma/regrade?release=${token}`)).status).toBe(404);
  });
});
