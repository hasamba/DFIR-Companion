import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Express } from "express";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, getServerLogger } from "../../src/server.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { CloudAccountVault } from "../../src/integrations/cloudAccounts/cloudAccountVault.js";
import { VaultKeyFile } from "../../src/integrations/cloudAccounts/vaultKeyFile.js";
import { awsKeyInput, fakeAwsSecret, gcpKeyInput, makeGcpKeyJson } from "../helpers/cloudAccountFixtures.js";

// #2378: a release whose `credential-detached` custody entries were written but whose detach did not
// happen (a later custody write, the chain-head pin or the vault write failed) is retried by closing
// the case again. The retry must not record the same detach twice. A case that comes back, has the
// account attached again and ends again is a second detach and gets a second entry.

let dir: string;
let vault: CloudAccountVault;
let cases: CaseStore;
let custody: CustodyStore;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "cloud-release-retry-"));
  vault = new CloudAccountVault(join(dir, "cloud-accounts"), new VaultKeyFile(join(dir, "k", "vault.key")));
  cases = new CaseStore(join(dir, "cases"));
  custody = new CustodyStore(cases);
  for (const id of ["c1", "c2"])
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
const close = (a: Express) => request(a).patch("/cases/c1/status").send({ status: "closed" });
const reopen = (a: Express) => request(a).patch("/cases/c1/status").send({ status: "open" });

/** Two accounts c1 shares with c2: closing c1 detaches both. */
function twoShared(): string[] {
  const a = vault.create(awsKeyInput("Shared AWS", fakeAwsSecret()), "c1").account;
  const g = vault.create(gcpKeyInput("Shared GCP", makeGcpKeyJson()), "c1").account;
  vault.attach(a.id, "c2");
  vault.attach(g.id, "c2");
  return [a.id, g.id];
}

/** How many `credential-detached` entries the case's log holds per account id. */
async function detachCounts(caseId: string): Promise<Record<string, number>> {
  const counts: Record<string, number> = {};
  for (const r of await custody.load(caseId))
    if (r.event === "credential-detached" && r.credential)
      counts[r.credential.accountId] = (counts[r.credential.accountId] ?? 0) + 1;
  return counts;
}

async function expectCleanChain(caseId: string): Promise<void> {
  expect(await custody.verifyChain(caseId)).toEqual([]);
  expect(await custody.verifyIntegrity(caseId)).toEqual([]);
}

describe("a retried release records each detach once (#2378)", () => {
  it("after the vault write failed behind recorded entries", async () => {
    const ids = twoShared();
    const a = app();
    vi.spyOn(vault, "releaseCase").mockImplementationOnce(() => {
      throw new Error("vault write failed");
    });
    const failed = await close(a);
    expect(failed.body.cloudCredentialsError, failed.text).toBeTruthy();
    for (const id of ids) expect(vault.view(id).caseIds).toEqual(["c1", "c2"]);

    const retry = await close(a);
    expect(retry.body.cloudCredentials, retry.text).toEqual({ deleted: 0, detached: 2 });
    for (const id of ids) expect(vault.view(id).caseIds).toEqual(["c2"]);
    expect(await detachCounts("c1")).toEqual({ [ids[0]]: 1, [ids[1]]: 1 });
    await expectCleanChain("c1");
  });

  it("after a custody write failed part-way through the accounts", async () => {
    const ids = twoShared();
    const a = app();
    const next = cases.nextCustodySeq.bind(cases);
    let calls = 0;
    vi.spyOn(cases, "nextCustodySeq").mockImplementation(async (caseId: string) => {
      calls += 1;
      if (calls === 2) throw new Error("custody disk full");
      return next(caseId);
    });
    const failed = await close(a);
    expect(failed.body.cloudCredentialsError, failed.text).toBeTruthy();
    for (const id of ids) expect(vault.view(id).caseIds).toEqual(["c1", "c2"]);

    expect((await close(a)).body.cloudCredentials).toEqual({ deleted: 0, detached: 2 });
    expect(await detachCounts("c1")).toEqual({ [ids[0]]: 1, [ids[1]]: 1 });
    await expectCleanChain("c1");
  });

  it("a case that comes back and ends again records a second, distinct detach", async () => {
    const ids = twoShared();
    const a = app();
    expect((await close(a)).body.cloudCredentials).toEqual({ deleted: 0, detached: 2 });
    expect((await reopen(a)).status).toBe(200);
    vault.attach(ids[0], "c1", "c2");
    expect((await close(a)).body.cloudCredentials).toEqual({ deleted: 0, detached: 1 });
    expect(await detachCounts("c1")).toEqual({ [ids[0]]: 2, [ids[1]]: 1 });
    const tokens = (await custody.load("c1"))
      .filter((r) => r.event === "credential-detached" && r.credential?.accountId === ids[0])
      .map((r) => r.credential?.releaseToken);
    expect(tokens.every(Boolean)).toBe(true);
    expect(new Set(tokens).size).toBe(2);
    await expectCleanChain("c1");
  });

  it("keeps no release token in the vault once the detach is done", async () => {
    twoShared();
    expect((await close(app())).body.cloudCredentials).toEqual({ deleted: 0, detached: 2 });
    expect(readFileSync(join(dir, "cloud-accounts", "accounts.json"), "utf8")).not.toContain("releaseTokens");
  });
});
