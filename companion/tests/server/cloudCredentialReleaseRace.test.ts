import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Express } from "express";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, getServerLogger } from "../../src/server.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { CloudAccountVault } from "../../src/integrations/cloudAccounts/cloudAccountVault.js";
import { VaultKeyFile } from "../../src/integrations/cloudAccounts/vaultKeyFile.js";
import { awsKeyInput, fakeAwsSecret } from "../helpers/cloudAccountFixtures.js";

// #2371: a case release records its `credential-detached` entries before it detaches. A concurrent
// attach, detach, delete or reset in that window used to make the custody log disagree with what the
// release did. Each test holds the release inside its custody write, fires the competing request,
// checks it is still waiting, lets the release go, and compares the case's custody log with the
// release's outcome.

let dir: string;
let vault: CloudAccountVault;
let cases: CaseStore;
let custody: CustodyStore;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "cloud-release-race-"));
  vault = new CloudAccountVault(join(dir, "cloud-accounts"), new VaultKeyFile(join(dir, "k", "vault.key")));
  cases = new CaseStore(join(dir, "cases"));
  custody = new CustodyStore(cases);
  for (const id of ["c1", "c2", "c3"])
    await cases.createCase({ caseId: id, name: `Case ${id}`, investigator: "i", aiProvider: null });
  const logger = getServerLogger();
  for (const level of ["info", "warn", "error", "debug"] as const)
    vi.spyOn(logger, level).mockImplementation(() => logger);
});
afterEach(() => {
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

const app = (): Express => createApp(cases, { cloudAccountVault: vault, custodyStore: custody });

const closeCase = (a: Express, caseId: string) =>
  request(a).patch(`/cases/${caseId}/status`).send({ status: "closed" });

const make = (name: string, ...caseIds: string[]): string => {
  const { id } = vault.create(awsKeyInput(name, fakeAwsSecret()), caseIds[0]).account;
  for (const c of caseIds.slice(1)) vault.attach(id, c);
  return id;
};

/** Holds every `credential-detached` custody write until open() is called. */
function holdDetachedWrites() {
  let open!: () => void;
  const gate = new Promise<void>((resolve) => (open = resolve));
  let reached!: () => void;
  const held = new Promise<void>((resolve) => (reached = resolve));
  const recordMany = custody.recordMany.bind(custody);
  vi.spyOn(custody, "recordMany").mockImplementation(async (caseId, inputs) => {
    if (inputs.some((input) => input.event === "credential-detached")) {
      reached();
      await gate;
    }
    return recordMany(caseId, inputs);
  });
  return { held, open };
}

/** Starts a request and reports whether it has answered yet. */
function start(req: request.Test) {
  let settled = false;
  const done = req.then((res) => {
    settled = true;
    return res;
  });
  return { done, settled: () => settled };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 30));

async function log(caseId: string) {
  const entries = await custody.load(caseId);
  const ids = (event: string) =>
    entries
      .filter((r) => r.event === event)
      .map((r) => r.credential?.accountId)
      .sort();
  return { detached: ids("credential-detached"), deleted: ids("credential-deleted") };
}

describe("a case release racing another change (#2371)", () => {
  it("sole -> shared: an attach waits, and the account is deleted with a deleted entry only", async () => {
    const shared = make("Shared", "c1", "c2");
    const sole = make("Sole", "c1");
    const { held, open } = holdDetachedWrites();
    const a = app();
    const release = start(closeCase(a, "c1"));
    await held;
    const attach = start(request(a).post(`/cases/c1/cloud-accounts/${sole}/attach`).send({ caseId: "c3" }));
    await tick();
    expect(attach.settled(), "the attach ran inside the release").toBe(false);
    open();
    const res = await release.done;
    expect(res.status, res.text).toBe(200);
    expect(res.body.cloudCredentials).toEqual({ deleted: 1, detached: 1 });
    expect((await attach.done).status).toBe(404);
    expect(await log("c1")).toEqual({ detached: [shared], deleted: [sole] });
  });

  it("shared -> sole: a detach waits, and the detached entry matches a detach", async () => {
    const shared = make("Shared", "c1", "c2");
    const { held, open } = holdDetachedWrites();
    const a = app();
    const release = start(closeCase(a, "c1"));
    await held;
    const detach = start(request(a).post(`/cases/c2/cloud-accounts/${shared}/detach`));
    await tick();
    expect(detach.settled(), "the detach ran inside the release").toBe(false);
    open();
    expect((await release.done).body.cloudCredentials).toEqual({ deleted: 0, detached: 1 });
    expect((await detach.done).status).toBe(200);
    expect(await log("c1")).toEqual({ detached: [shared], deleted: [] });
    expect(vault.view(shared).caseIds).toEqual([]);
  });

  it("two cases closing at once: each log matches what its own release did", async () => {
    const shared = make("Shared", "c1", "c2");
    const a = app();
    const [r1, r2] = await Promise.all([closeCase(a, "c1"), closeCase(a, "c2")]);
    const outcomes = [r1.body.cloudCredentials, r2.body.cloudCredentials];
    expect(outcomes).toEqual(
      expect.arrayContaining([
        { deleted: 0, detached: 1 },
        { deleted: 1, detached: 0 },
      ]),
    );
    const detacher = r1.body.cloudCredentials.detached ? "c1" : "c2";
    const deleter = detacher === "c1" ? "c2" : "c1";
    expect(await log(detacher)).toEqual({ detached: [shared], deleted: [] });
    expect(await log(deleter)).toEqual({ detached: [], deleted: [shared] });
    expect(vault.list()).toEqual([]);
  });

  it("a delete from the list waits, so the detached entry is not followed by a contradiction", async () => {
    const shared = make("Shared", "c1", "c2");
    const { held, open } = holdDetachedWrites();
    const a = app();
    const release = start(closeCase(a, "c1"));
    await held;
    const del = start(request(a).delete(`/cloud-accounts/${shared}`));
    await tick();
    expect(del.settled(), "the delete ran inside the release").toBe(false);
    open();
    expect((await release.done).body.cloudCredentials).toEqual({ deleted: 0, detached: 1 });
    expect((await del.done).status).toBe(204);
    expect(await log("c1")).toEqual({ detached: [shared], deleted: [] });
    expect(await log("c2")).toEqual({ detached: [], deleted: [shared] });
  });

  it("a vault reset waits for the release", async () => {
    const shared = make("Shared", "c1", "c2");
    const { held, open } = holdDetachedWrites();
    const a = app();
    const release = start(closeCase(a, "c1"));
    await held;
    const reset = start(request(a).post("/cloud-accounts/reset").send({ confirm: true }));
    await tick();
    expect(reset.settled(), "the reset ran inside the release").toBe(false);
    open();
    expect((await release.done).body.cloudCredentials).toEqual({ deleted: 0, detached: 1 });
    expect((await reset.done).body).toEqual({ removed: 1 });
    expect(await log("c1")).toEqual({ detached: [shared], deleted: [] });
  });

  it("a failed custody write still stops the release, and the vault lock is free afterwards", async () => {
    const shared = make("Shared", "c1", "c2");
    vi.spyOn(custody, "recordMany").mockRejectedValueOnce(new Error("custody disk full"));
    const a = app();
    const res = await closeCase(a, "c1");
    expect(res.body.cloudCredentialsError).toMatch(/could not be deleted/i);
    expect(vault.view(shared).caseIds).toEqual(["c1", "c2"]);
    // The lock was let go: a locked route runs at once.
    const detach = await request(a).post(`/cases/c2/cloud-accounts/${shared}/detach`);
    expect(detach.status, detach.text).toBe(200);
  });
});
