// Client profiles on the public demo (#2670). The demo runs with no login (public-demo) and
// DFIR_DEMO_MODE=1, whose gate lets every GET through — so a route that answers an instance
// administrator answers any stranger there. Client profiles hold one client's reviewed baseline,
// marks, versions and audit trail: refused outright on the demo, GET included, at the gate AND
// at the route (the cloud-accounts precedent, #2308).
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { ClientProfileStore } from "../../src/analysis/clientProfileStore.js";
import { newProfile } from "../../src/analysis/clientProfile.js";
import { HuntClientLinkStore } from "../../src/analysis/huntClientLink.js";
import { HuntInventoryStore } from "../../src/analysis/huntInventoryStore.js";
import { IncidentTypeStore } from "../../src/analysis/incidentTypeStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { isClientDataRoutePath } from "../../src/auth/policy.js";
import { registerClientProfileRoutes } from "../../src/routes/clientProfiles.js";
import { registerHuntClientRoutes } from "../../src/routes/huntClient.js";
import type { RouteContext } from "../../src/routes/context.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import express from "express";

async function world(demoMode: boolean) {
  const root = await mkdtemp(join(tmpdir(), "dfir-hunt-demo-"));
  const cases = new CaseStore(join(root, "cases"));
  const profiles = new ClientProfileStore(join(root, "client-profiles"));
  const links = new HuntClientLinkStore(cases);
  const incidentTypes = new IncidentTypeStore(cases, join(root, "incident-types"));
  for (const id of ["c1", "c2"])
    await cases.createCase({ caseId: id, name: `Hunt ${id}`, investigator: "i", aiProvider: null });
  await incidentTypes.saveRecord("c1", "threat-hunt");
  const profile = await profiles.create(newProfile({ name: "Client A" }, "admin", "2026-11-01T00:00:00Z"));
  for (const id of ["c1", "c2"])
    await links.save(id, { clientId: profile.id, linkedAt: "2026-11-01T00:00:00Z", linkedBy: "admin" });
  const options = {
    demoMode,
    stateStore: new StateStore(cases),
    veloHuntStore: new VeloHuntStore(cases),
    incidentTypeStore: incidentTypes,
    clientProfileStore: profiles,
    huntClientLinkStore: links,
    huntInventoryStore: new HuntInventoryStore(cases),
  };
  return { app: createApp(cases, options), cases, options, profileId: profile.id };
}

const CLIENT_DATA_GETS = (pid: string) => [
  "/client-profiles",
  `/client-profiles/${pid}`,
  "/cases/c1/hunt/client",
  "/cases/c1/hunt/candidates",
  "/cases/c1/hunt/confirm-list.csv",
  "/cases/c1/hunt/confirm-list.md",
];

describe("client profiles on the public demo (#2670)", () => {
  it("refuses every client-data read, GET included, with no login", async () => {
    const { app, profileId } = await world(true);
    for (const url of CLIENT_DATA_GETS(profileId)) {
      const res = await request(app).get(url);
      expect(res.status, url).toBe(403);
      expect(res.body.demo, url).toBe(true);
      expect(JSON.stringify(res.body), url).not.toContain("Client A");
    }
  });

  it("refuses odd spellings of the same routes (case, trailing slash, encoding)", async () => {
    const { app, profileId } = await world(true);
    for (const url of [
      "/Client-Profiles",
      "/client-profiles/",
      `/CLIENT-PROFILES/${profileId}`,
      "/cases/c1/HUNT/client",
    ]) {
      const res = await request(app).get(url);
      expect(res.status, url).toBe(403);
    }
    expect(isClientDataRoutePath("/%63lient-profiles")).toBe(true);
    expect(isClientDataRoutePath("/cases/c1/hunt/status")).toBe(false);
  });

  it("the routes refuse on their own, behind no gate (second line)", async () => {
    const { options, cases, profileId } = await world(true);
    const app = express();
    const ctx = {
      options,
      store: cases,
      readUnlockState: () => ({ unlocked: true, remembered: false }),
    } as unknown as RouteContext;
    registerClientProfileRoutes(app, ctx);
    registerHuntClientRoutes(app, ctx);
    for (const url of CLIENT_DATA_GETS(profileId)) {
      const res = await request(app).get(url);
      expect(res.status, url).toBe(403);
      expect(res.body.demo, url).toBe(true);
    }
  });

  it("the hunt re-grade stays refused on the demo (a POST)", async () => {
    const { app } = await world(true);
    expect((await request(app).post("/cases/c1/hunt/regrade").send({})).status).toBe(403);
  });

  it("outside the demo the single-user owner still reads them", async () => {
    const { app, profileId } = await world(false);
    expect((await request(app).get(`/client-profiles/${profileId}`)).status).toBe(200);
    const info = await request(app).get("/cases/c1/hunt/client");
    expect(info.status).toBe(200);
    expect(info.body.earlierHunts.map((h: { caseId: string }) => h.caseId)).toEqual(["c2"]);
  });
});
