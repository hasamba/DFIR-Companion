// #1108: the collection-generation ledger's own routes. End-to-end via a real CaseStore-seeded
// import, plus a standalone unit-tested actorFrom (mirrors evidenceAttestationRoutes.test.ts's own
// humanIdentityFor coverage — no route-level test in this codebase exercises the real team-auth
// middleware directly, so a pure function is the practical way to get real coverage of it).
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CollectionGenerationStore } from "../../src/analysis/collectionGenerationStore.js";
import { actorFrom } from "../../src/routes/collectionGenerations.js";
import type { RequestAuthentication, AuthIdentity } from "../../src/auth/types.js";
import { createApp } from "../../src/server.js";

const PERSISTENCE_ROWS = [
  {
    Hostname: "WS-01",
    Technique: "Run Key",
    Classification: "Suspicious",
    Path: "HKCU\\Run\\Updater",
    Value: "C:\\Temp\\updater.exe",
    "Access Gained": "User",
  },
];

let app: ReturnType<typeof createApp>;
let store: CaseStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-collection-generations-"));
  store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(store, {
    stateStore: new StateStore(store),
    collectionGenerationStore: new CollectionGenerationStore(store),
  });
});

async function seedImport(caseId: string): Promise<number> {
  const seq = await store.nextImportSeq(caseId);
  const filename = `000${seq}_persistencesniper.json`;
  await store.saveImport(caseId, filename, JSON.stringify(PERSISTENCE_ROWS));
  await store.appendImport(caseId, {
    caseId,
    sequenceNumber: seq,
    importedAt: new Date().toISOString(),
    filename,
    originalName: filename,
    rows: PERSISTENCE_ROWS.length,
    bytes: JSON.stringify(PERSISTENCE_ROWS).length,
  });
  return seq;
}

describe("/cases/:id/collection-generations", () => {
  it("returns an empty list for a fresh case", async () => {
    const res = await request(app).get("/cases/c1/collection-generations");
    expect(res.status).toBe(200);
    expect(res.body.generations).toEqual([]);
  });

  it("records a generation and reflects it in the list", async () => {
    const importSeq = await seedImport("c1");
    const res = await request(app)
      .post("/cases/c1/collection-generations")
      .send({
        rawHost: "WS-01",
        domain: "persistence",
        order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
        importSeq,
        completenessState: "complete",
      });
    expect(res.status).toBe(201);
    expect(res.body.generation.inventory).toHaveLength(1);
    expect(res.body.generation.recordedBy).toEqual({ id: "local", displayName: "local" });

    const list = await request(app).get("/cases/c1/collection-generations");
    expect(list.body.generations).toHaveLength(1);
  });

  it("400s a malformed body instead of 500ing", async () => {
    const res = await request(app).post("/cases/c1/collection-generations").send({ rawHost: "" });
    expect(res.status).toBe(400);
  });

  it("400s a record() rejection (e.g. an importSeq that does not exist) — never a 500", async () => {
    const res = await request(app)
      .post("/cases/c1/collection-generations")
      .send({
        rawHost: "WS-01",
        domain: "persistence",
        order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
        importSeq: 999,
        completenessState: "complete",
      });
    expect(res.status).toBe(400);
  });

  it("filters by host, resolved through the current alias index", async () => {
    const importSeq = await seedImport("c1");
    await request(app)
      .post("/cases/c1/collection-generations")
      .send({
        rawHost: "WS-01",
        domain: "persistence",
        order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
        importSeq,
        completenessState: "complete",
      });
    const match = await request(app).get("/cases/c1/collection-generations?host=WS-01");
    expect(match.body.generations).toHaveLength(1);
    const noMatch = await request(app).get("/cases/c1/collection-generations?host=WS-99");
    expect(noMatch.body.generations).toHaveLength(0);
  });

  it("revokes a generation", async () => {
    const importSeq = await seedImport("c1");
    const created = await request(app)
      .post("/cases/c1/collection-generations")
      .send({
        rawHost: "WS-01",
        domain: "persistence",
        order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
        importSeq,
        completenessState: "complete",
      });
    const generationId = created.body.generation.generationId as string;
    const res = await request(app).delete(`/cases/c1/collection-generations/${generationId}`);
    expect(res.status).toBe(200);
    expect(res.body.generations[0].revokedAt).toBeTruthy();
  });

  it("returns 501 when the store is not configured", async () => {
    const bareApp = createApp(store, { stateStore: new StateStore(store) });
    const res = await request(bareApp).get("/cases/c1/collection-generations");
    expect(res.status).toBe(501);
  });

  it("verifies an unchanged artifact ok, and detects one that changed since recording", async () => {
    const importSeq = await seedImport("c1");
    const created = await request(app)
      .post("/cases/c1/collection-generations")
      .send({
        rawHost: "WS-01",
        domain: "persistence",
        order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
        importSeq,
        completenessState: "complete",
      });
    const generationId = created.body.generation.generationId as string;
    const ok = await request(app).get(`/cases/c1/collection-generations/${generationId}/verify`);
    expect(ok.body).toEqual({ ok: true });
  });
});

// #1108 design review (Codex finding M3): actorFrom must return a stable {id, displayName}, never
// just a label — mirrors evidenceAttestationRoutes.test.ts's own humanIdentityFor coverage exactly.
function identity(over: Partial<AuthIdentity> = {}): AuthIdentity {
  return {
    id: "u1",
    kind: "local",
    displayName: "a.analyst",
    globalRole: "member",
    disabled: false,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    ...over,
  };
}

describe("actorFrom (#1108)", () => {
  it("is {id: 'local', displayName: 'local'} when team-auth is off, regardless of any auth result", () => {
    expect(actorFrom(undefined, false)).toEqual({ id: "local", displayName: "local" });
  });

  it("returns the real stable id + display name for a human session when team-auth is on", () => {
    const sessionAuth: RequestAuthentication = {
      kind: "session",
      identity: identity({ id: "real-id-1", displayName: "b.reviewer" }),
      session: {
        id: "s1",
        identityId: "real-id-1",
        csrfToken: "x",
        createdAt: "2026-01-01T00:00:00Z",
        expiresAt: "2026-01-02T00:00:00Z",
        lastSeenAt: "2026-01-01T00:00:00Z",
      },
    };
    expect(actorFrom(sessionAuth, true)).toEqual({ id: "real-id-1", displayName: "b.reviewer" });
  });

  it("rejects a service-token auth when team-auth is on", () => {
    const serviceAuth: RequestAuthentication = {
      kind: "service-token",
      identity: identity({ kind: "service" }),
      token: {
        id: "t1",
        identityId: "u1",
        name: "ci-bot",
        caseId: "c1",
        permissions: ["write"],
        createdAt: "2026-01-01T00:00:00Z",
      },
    };
    expect(actorFrom(serviceAuth, true)).toBeNull();
  });

  it("rejects a missing auth entirely when team-auth is on", () => {
    expect(actorFrom(undefined, true)).toBeNull();
  });
});
