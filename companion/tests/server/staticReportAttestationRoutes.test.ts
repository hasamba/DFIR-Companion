// #1316: analyst-attested binding of a static-analysis report to a subject host. Real olevba
// parser output seeded into a real StateStore, real attestation store, real routes end to end.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { StaticReportAttestationStore } from "../../src/analysis/staticReportAttestationStore.js";
import { parseOlevbaResult } from "../../src/analysis/olevbaResultImport.js";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { createApp } from "../../src/server.js";
import { provisionServiceToken } from "../helpers/serviceTokenAuth.js";

const ROUTE = "/cases/c1/static-report-attestations";
const SHA = "1".repeat(64);

// A real olevba -j document (shape per olevbaResultImport.test.ts) with an AutoOpen + download
// capability pair, so the parser emits a compound lead carrying documentPath + reportFingerprint.
function olevbaDoc(file: string): string {
  return JSON.stringify([
    { type: "MetaInformation", script_name: "olevba", version: "0.60.2" },
    {
      type: "OLE",
      file,
      json_conversion_successful: true,
      macros: [],
      analysis: [
        { type: "AutoExec", keyword: "AutoOpen", description: "Runs when the Word document is opened" },
        {
          type: "Suspicious",
          keyword: "URLDownloadToFile",
          description: "May download files from the Internet",
        },
      ],
    },
  ]);
}

function olevbaEvents(file: string): { events: ForensicEvent[]; fingerprint: string } {
  const parsed = parseOlevbaResult(olevbaDoc(file));
  if (!parsed) throw new Error("fixture did not parse");
  const events = parsed.events.map((e) => ({
    id: e.id,
    timestamp: e.timestamp,
    description: e.description,
    severity: e.severity,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: e.sources,
    canonical: e.canonical,
  })) as ForensicEvent[];
  const lead = events.find((e) => e.canonical?.olevbaCompoundLead);
  if (!lead?.canonical?.olevbaCompoundLead) throw new Error("no compound lead in fixture");
  return { events, fingerprint: lead.canonical.olevbaCompoundLead.reportFingerprint };
}

function victimRow(id: string, host: string, path: string, sha256?: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-09-10T10:00:00Z",
    description: `file ${path}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: host,
    path,
    ...(sha256 ? { sha256 } : {}),
    sources: ["Sysmon"],
    canonical: createCanonicalEvent({
      event: { category: "file", type: "create" },
      time: { observed: "2026-09-10T10:00:00Z", normalized: "2026-09-10T10:00:00Z" },
      evidence: { rawRecords: [{ source: "sysmon", locator: `row:${id}` }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

function stateWith(events: ForensicEvent[]): InvestigationState {
  return { ...emptyState("c1"), forensicTimeline: events, updatedAt: new Date().toISOString() };
}

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-static-report-att-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const app = createApp(cases, {
    stateStore,
    staticReportAttestationStore: new StaticReportAttestationStore(cases),
  });
  return { app, stateStore, cases };
}

describe(ROUTE, () => {
  it("returns 501 when the attestation store is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-static-report-att-bare-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const bare = createApp(cases, {});
    expect((await request(bare).get(ROUTE)).status).toBe(501);
  });

  it("lists an empty audit trail for a fresh case", async () => {
    const { app } = await makeApp();
    const res = await request(app).get(ROUTE);
    expect(res.status).toBe(200);
    expect(res.body.attestations).toEqual([]);
  });

  it("rejects a fingerprint no event in the case carries (400, not 500)", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(stateWith([]));
    const res = await request(app)
      .post(ROUTE)
      .send({ reportFingerprint: "9".repeat(64), subjectHost: "ws-01" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/no event/);
  });

  it("creates an attestation with the tool derived from the report, annotates the list read-time, and joins the flagship E:/C: case", async () => {
    const { app, stateStore } = await makeApp();
    const { events, fingerprint } = olevbaEvents("E:\\Users\\bob\\invoice.docm");
    const victim = victimRow("v1", "WS-01", "C:\\Users\\bob\\invoice.docm");
    await stateStore.save(
      stateWith([...events, victim, victimRow("v2", "ws-02", "C:\\Users\\bob\\invoice.docm")]),
    );

    const created = await request(app)
      .post(ROUTE)
      .send({
        reportFingerprint: fingerprint,
        subjectHost: "ws-01",
        evidenceVolume: { mountPoint: "E:", originalVolume: "C:" },
      });
    expect(created.status).toBe(200);
    expect(created.body.attestation.tool).toBe("olevba");
    expect(created.body.attestation.attestedBy).toBe("local");
    expect(created.body.attestation.evidenceVolume.mountPoint).toEqual({ volume: "e", volumeKind: "drive" });

    const list = await request(app).get(ROUTE);
    expect(list.body.attestations[0]).toMatchObject({
      subjectHostCanonical: "ws-01",
      subjectHostKnown: true,
      reportPresent: true,
    });

    const matches = await request(app).get(`${ROUTE}/${created.body.attestation.id}/matches`);
    expect(matches.status).toBe(200);
    expect(matches.body.path.rows.map((r: { eventId: string }) => r.eventId)).toEqual(["v1"]);
    expect(matches.body.path.rows[0].identity).toBe("path-only");
    expect(matches.body.caveat).toMatch(/never a verification/);
    expect(matches.body.contract).toMatch(/command line/);
    expect(matches.body.hash.skipped).toMatch(/no digest available/);
    expect(list.body.caveat).toMatch(/never a verification/);
  });

  it("rejects an analyst digest that disagrees with the tool-reported one, and a second active attestation for the same report (400)", async () => {
    const { app, stateStore } = await makeApp();
    const { events, fingerprint } = olevbaEvents("C:\\x\\a.docm");
    await stateStore.save(stateWith(events));
    const first = await request(app)
      .post(ROUTE)
      .send({ reportFingerprint: fingerprint, subjectHost: "ws-01", documentSha256: SHA });
    expect(first.status).toBe(200);
    expect(first.body.attestation.digestCrossCheck).toBe("none"); // olevba reports no digest
    const second = await request(app)
      .post(ROUTE)
      .send({ reportFingerprint: fingerprint, subjectHost: "ws-02" });
    expect(second.status).toBe(400);
    expect(second.body.error).toMatch(/already has an active attestation/);
    const hashedReport = await request(app)
      .post(ROUTE)
      .send({ reportFingerprint: fingerprint, subjectHost: "ws-01", documentSha256: fingerprint });
    expect(hashedReport.status).toBe(400);
  });

  it("hash rows match on any host and carry whether the host is the attested subject", async () => {
    const { app, stateStore } = await makeApp();
    const { events, fingerprint } = olevbaEvents("C:\\x\\a.docm");
    await stateStore.save(stateWith([...events, victimRow("h1", "ws-07", "D:\\dl\\a.docm", SHA)]));
    const created = await request(app)
      .post(ROUTE)
      .send({ reportFingerprint: fingerprint, subjectHost: "ws-01", documentSha256: SHA });
    const matches = await request(app).get(`${ROUTE}/${created.body.attestation.id}/matches`);
    expect(matches.body.hash.rows).toHaveLength(1);
    expect(matches.body.hash.rows[0]).toMatchObject({
      eventId: "h1",
      host: "ws-07",
      hostIsAttestedSubject: false,
      identity: "analyst-attested-digest",
    });
  });

  it("revokes by id (404 on unknown), keeps a revoked attestation's matches viewable with the revoked prefix", async () => {
    const { app, stateStore } = await makeApp();
    const { events, fingerprint } = olevbaEvents("C:\\x\\a.docm");
    await stateStore.save(stateWith([...events, victimRow("v1", "ws-01", "C:\\x\\a.docm")]));
    const created = await request(app)
      .post(ROUTE)
      .send({ reportFingerprint: fingerprint, subjectHost: "ws-01" });
    const id = created.body.attestation.id as string;
    expect((await request(app).delete(`${ROUTE}/nope`)).status).toBe(404);
    const revoked = await request(app).delete(`${ROUTE}/${id}`).send({ reason: "wrong host" });
    expect(revoked.status).toBe(200);
    expect(revoked.body.attestations[0].revokedReason).toBe("wrong host");
    const matches = await request(app).get(`${ROUTE}/${id}/matches`);
    expect(matches.body.attestationRevoked).toBe(true);
    expect(matches.body.path.rows[0].basis).toMatch(/^ATTESTATION REVOKED — /);
    expect((await request(app).get(`${ROUTE}/ghost/matches`)).status).toBe(404);
  });

  it("rejects a malformed body with 400", async () => {
    const { app } = await makeApp();
    expect((await request(app).post(ROUTE).send({ subjectHost: "ws-01" })).status).toBe(400);
    expect(
      (await request(app).post(ROUTE).send({ reportFingerprint: "x", subjectHost: "ws-01" })).status,
    ).toBe(400);
  });
});

describe(`${ROUTE} with team-auth on`, () => {
  async function teamApp() {
    const root = await mkdtemp(join(tmpdir(), "dfir-static-report-att-teamauth-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const store = new AuthStore(join(root, "auth.sqlite"));
    const token = await provisionServiceToken(store, "c1", ["write"]);
    const teamAuth = new TeamAuth({
      store,
      bootstrapToken: "test-bootstrap-token",
      cookieSecure: false,
      sessionTtlMs: 60 * 60_000,
    });
    const app = createApp(cases, {
      teamAuth,
      stateStore: new StateStore(cases),
      staticReportAttestationStore: new StaticReportAttestationStore(cases),
    });
    return { app, token };
  }

  it("rejects POST and DELETE with no session identity (401 from the upstream gate)", async () => {
    const { app } = await teamApp();
    expect(
      (await request(app).post(ROUTE).send({ reportFingerprint: SHA, subjectHost: "ws-01" })).status,
    ).toBe(401);
    expect((await request(app).delete(`${ROUTE}/x`)).status).toBe(401);
  });

  it("rejects POST and DELETE from a real, authenticated service token — the route's own 403 (#1169)", async () => {
    const { app, token } = await teamApp();
    const post = await request(app)
      .post(ROUTE)
      .set("Authorization", `Bearer ${token}`)
      .send({ reportFingerprint: SHA, subjectHost: "ws-01" });
    expect(post.status).toBe(403);
    const del = await request(app).delete(`${ROUTE}/x`).set("Authorization", `Bearer ${token}`);
    expect(del.status).toBe(403);
  });
});
