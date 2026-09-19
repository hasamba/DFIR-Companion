// #1363: requested ↔ granted ↔ used, by package on the analyst's subject device. Real MobSF and
// LEAPP parser output seeded into a real StateStore; the MobSF report attested to the device
// through the UNCHANGED #1316 route; the chains route read end to end.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { StaticReportAttestationStore } from "../../src/analysis/staticReportAttestationStore.js";
import { parseMobsfPermissions } from "../../src/analysis/mobsfPermissionImport.js";
import { parseLeappTsv } from "../../src/analysis/mobileLeappImport.js";
import { registryEntry } from "../../src/analysis/mobileOriginRegistry.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";
import { createApp } from "../../src/server.js";

const ROUTE = "/cases/c1/mobile-permission-chains";
const ATTEST = "/cases/c1/static-report-attestations";
const SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
let seq = 0;

function mobsfEvents(pkg: string): { events: ForensicEvent[]; fingerprint: string } {
  const text = JSON.stringify({
    version: "4.5.0",
    file_name: "s.apk",
    app_name: "S",
    package_name: pkg,
    md5: "d41d8cd98f00b204e9800998ecf8427e",
    sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    sha256: SHA,
    apkid: {},
    permissions: {
      "android.permission.CAMERA": { status: "dangerous", info: "i", description: "d" },
      "android.permission.READ_SMS": { status: "dangerous", info: "i", description: "d" },
    },
  });
  const parsed = parseMobsfPermissions(text)!;
  const events = parsed.events.map((e) => ({
    ...(e as unknown as ForensicEvent),
    id: `mb${++seq}`,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  }));
  const fingerprint = events[0].canonical!.mobileRequestedPermission!.reportFingerprint;
  return { events, fingerprint };
}

function leappRow(artifact: string, values: Record<string, string>, device = "Subject Pixel"): ForensicEvent {
  const entry = registryEntry(artifact)!;
  const cells = entry.headers.map((h) => values[h] ?? "");
  const events = parseLeappTsv([entry.headers.join("\t"), cells.join("\t")].join("\n"), `${entry.name}.tsv`, {
    platform: "android",
    device,
  }).events;
  return {
    ...(events[0] as ForensicEvent),
    id: `lp${++seq}`,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

function stateWith(events: ForensicEvent[]): InvestigationState {
  return { ...emptyState("c1"), forensicTimeline: events, updatedAt: new Date().toISOString() };
}

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-mobile-perm-chain-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const app = createApp(cases, {
    stateStore,
    staticReportAttestationStore: new StaticReportAttestationStore(cases),
  });
  return { app, stateStore };
}

describe(ROUTE, () => {
  it("501 when the state store is not configured; 400 without a device, or with an overlong one", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-mobile-perm-chain-bare-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    expect((await request(createApp(cases, {})).get(`${ROUTE}?device=x`)).status).toBe(501);

    const { app } = await makeApp();
    const missing = await request(app).get(ROUTE);
    expect(missing.status).toBe(400);
    expect(missing.body.error).toMatch(/device/);
    expect((await request(app).get(`${ROUTE}?device=${"x".repeat(121)}`)).status).toBe(400);
  });

  it("end to end: attest the MobSF report to the device through the #1316 route, then read the chain", async () => {
    const { app, stateStore } = await makeApp();
    const { events, fingerprint } = mobsfEvents("com.example.app");
    await stateStore.save(
      stateWith([
        ...events,
        leappRow("Permission Grants (Permission Store)", {
          "Package Name": "com.example.app",
          Permission: "android.permission.CAMERA",
          Granted: "Yes",
        }),
        leappRow("App Ops Permissions", {
          "Access Timestamp": "2026-06-03 09:00:00",
          "Package Name": "com.example.app",
          Permission: "CAMERA",
        }),
        leappRow("installedappsGass", {
          "Bundle ID": "com.example.app",
          "SHA-256 Hash": SHA,
          "Version Code": "1",
        }),
      ]),
    );

    // Before the attestation: a chain exists for the package, but the report is only a candidate.
    const before = await request(app).get(`${ROUTE}?device=Subject%20Pixel`);
    expect(before.status).toBe(200);
    expect(before.body.device).toBe("subject pixel");
    expect(before.body.chains[0].reports).toEqual([]);
    expect(before.body.chains[0].permissions).toEqual([]);
    expect(before.body.unboundCandidates).toEqual([
      expect.objectContaining({ fingerprint, package: "com.example.app" }),
    ]);

    const created = await request(app)
      .post(ATTEST)
      .send({ reportFingerprint: fingerprint, subjectHost: "Subject Pixel" });
    expect(created.status).toBe(200);
    expect(created.body.attestation.tool).toBe("mobsf");
    expect(created.body.attestation.toolReportedSha256).toBe(SHA);

    const after = await request(app).get(`${ROUTE}?device=subject%20pixel`);
    expect(after.status).toBe(200);
    expect(after.body.unboundCandidates).toEqual([]);
    const chain = after.body.chains[0];
    expect(chain.reports).toEqual([
      expect.objectContaining({
        fingerprint,
        attestationId: created.body.attestation.id,
        hashAgreement: "agrees",
      }),
    ]);
    const byName = Object.fromEntries(chain.permissions.map((p: { name: string }) => [p.name, p]));
    expect(byName.CAMERA).toMatchObject({ grantState: "granted", case: "requested-granted-used" });
    expect(byName.CAMERA.used[0].locator).toBe("App Ops Permissions:row:1");
    expect(byName.READ_SMS).toMatchObject({ grantState: "no-grant-record", case: "requested-only" });
    expect(after.body.caveat).toMatch(/never proof the user consciously granted/);
    expect(after.body.diagnostics).toMatchObject({ attestations: 1, truncated: [] });

    // Revoke it: the join disappears, nothing was persisted on the timeline.
    const revoked = await request(app)
      .delete(`${ATTEST}/${created.body.attestation.id}`)
      .send({ reason: "wrong device" });
    expect(revoked.status).toBe(200);
    const gone = await request(app).get(`${ROUTE}?device=subject%20pixel`);
    expect(gone.body.chains[0].reports).toEqual([]);
    expect(gone.body.unboundCandidates).toHaveLength(1);
    const state = await stateStore.load("c1");
    for (const e of state.forensicTimeline) expect(e.description).not.toMatch(/requested-granted-used/);
  });

  it("an unknown case reads as an empty chain set, never a 500", async () => {
    const { app } = await makeApp();
    const res = await request(app).get(`/cases/nope/mobile-permission-chains?device=x`);
    expect(res.status).toBe(200);
    expect(res.body.chains).toEqual([]);
  });
});
