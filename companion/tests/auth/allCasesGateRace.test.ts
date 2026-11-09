import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth, type CaseLifecycle } from "../../src/auth/teamAuth.js";
import type { AuthIdentity } from "../../src/auth/types.js";

/**
 * An all-cases token's case-state lookup awaits the filesystem (#2474). Anything that changes while
 * it is pending — the token revoked, the owner disabled, the owner's role removed — must still stop
 * the request. Each test holds the lookup open, makes the change, then releases it.
 */

interface Held {
  release: () => void;
  started: Promise<void>;
}

function holdingLookup(): { held: () => Held; lookup: (caseId: string) => Promise<CaseLifecycle> } {
  let current: Held | undefined;
  let signalStarted: () => void = () => undefined;
  let release: () => void = () => undefined;
  const reset = () => {
    const started = new Promise<void>((resolve) => (signalStarted = resolve));
    const released = new Promise<void>((resolve) => (release = resolve));
    current = { release: () => release(), started };
    return released;
  };
  let released = reset();
  return {
    held: () => current as Held,
    lookup: async () => {
      signalStarted();
      await released;
      released = reset();
      return "open";
    },
  };
}

describe("all-cases token gate races (#2474)", () => {
  let store: AuthStore;
  let admin: AuthIdentity;
  let owner: AuthIdentity;
  let token: string;
  let tokenId: string;
  let app: express.Express;
  let gate: ReturnType<typeof holdingLookup>;

  beforeEach(async () => {
    store = new AuthStore(join(await mkdtemp(join(tmpdir(), "dfir-all-cases-race-")), "auth.sqlite"));
    admin = await store.bootstrapLocalAdministrator({
      username: "admin",
      displayName: "Admin",
      password: "correct horse battery staple",
    });
    owner = await store.createLocalIdentity(
      { username: "analyst", displayName: "Analyst", password: "a sufficiently long password" },
      admin,
    );
    store.setCaseRole("c1", owner.id, "investigator", admin);
    const created = store.createAllCasesServiceToken(
      {
        name: "extension",
        permissions: ["capture", "write"],
        expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      },
      owner,
    );
    token = created.token;
    tokenId = created.record.id;
    const auth = new TeamAuth({ store, cookieSecure: false, sessionTtlMs: 60_000 });
    gate = holdingLookup();
    app = express();
    app.use(express.json());
    app.use(auth.middleware({ caseLifecycleOf: gate.lookup }));
    app.get("/cases", (req, res) => {
      res.json([...(auth.visibleCaseIds(req) ?? [])]);
    });
    app.post("/captures", (_req, res) => {
      res.status(201).json({ ok: true });
    });
  });

  const captureC1 = () =>
    request(app).post("/captures").set("Authorization", `Bearer ${token}`).send({ caseId: "c1" });

  it("admits the request when nothing changed during the lookup", async () => {
    const pending = captureC1().then((res) => res.status);
    await gate.held().started;
    gate.held().release();
    expect(await pending).toBe(201);
  });

  it("refuses a request whose token was revoked while the lookup was pending", async () => {
    const pending = captureC1().then((res) => res.status);
    await gate.held().started;
    store.revokeServiceToken(tokenId, admin);
    gate.held().release();
    expect(await pending).toBe(401);
  });

  it("refuses a request whose owner was disabled while the lookup was pending", async () => {
    const pending = captureC1().then((res) => res.status);
    await gate.held().started;
    await store.updateIdentity(owner.id, { disabled: true }, admin);
    gate.held().release();
    expect(await pending).toBe(401);
  });

  it("refuses a capture whose owner lost the case role while the lookup was pending", async () => {
    const pending = captureC1().then((res) => res.status);
    await gate.held().started;
    store.removeCaseRole("c1", owner.id, admin);
    gate.held().release();
    expect(await pending).toBe(404);
  });

  it("drops a case from the list when the role is removed while the lookup was pending", async () => {
    const pending = request(app)
      .get("/cases")
      .set("Authorization", `Bearer ${token}`)
      .then((res) => res.body as string[]);
    await gate.held().started;
    store.removeCaseRole("c1", owner.id, admin);
    gate.held().release();
    expect(await pending).toEqual([]);
  });
});
