import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { CaseStore } from "../../src/storage/caseStore.js";
import { hashCasePassword, signUnlockToken, unlockCookieName } from "../../src/analysis/casePassword.js";
import { authorizeWsUpgrade } from "../../src/live/wsGate.js";

let store: CaseStore;
let secret: Buffer;

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-wsgate-")));
  await store.createCase({ caseId: "open", name: "n", investigator: "i", aiProvider: null });
  await store.createCase({ caseId: "locked", name: "n", investigator: "i", aiProvider: null });
  secret = randomBytes(32);
});

// The gate's dependencies, plus whatever headers the test wants to simulate.
const deps = () => ({ store, secret, allowedOrigins: [] as string[] });

const upgrade = (url: string, headers: Record<string, string> = {}) =>
  authorizeWsUpgrade({ url, headers: { host: "127.0.0.1:4773", ...headers } }, deps());

async function lockCase(): Promise<string> {
  const password = hashCasePassword("secret123");
  await store.updateCaseMeta("locked", { password });
  return signUnlockToken("locked", password.salt, secret, 60_000, false);
}

describe("authorizeWsUpgrade (#212)", () => {
  it("admits a subscriber to a case with no password", async () => {
    const result = await upgrade("/ws?caseId=open");
    expect(result.ok).toBe(true);
    expect(result.ok && result.caseId).toBe("open");
  });

  it("refuses a locked case when the socket carries no unlock cookie", async () => {
    await lockCase();
    const result = await upgrade("/ws?caseId=locked");
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toMatch(/locked/i);
  });

  it("admits a locked case when the socket carries a valid unlock cookie", async () => {
    const token = await lockCase();
    const result = await upgrade("/ws?caseId=locked", { cookie: `${unlockCookieName("locked")}=${token}` });
    expect(result.ok).toBe(true);
  });

  it("refuses a locked case when the unlock cookie is forged", async () => {
    await lockCase();
    const result = await upgrade("/ws?caseId=locked", { cookie: `${unlockCookieName("locked")}=not-a-real-token` });
    expect(result.ok).toBe(false);
  });

  it("refuses an unlock cookie minted for a DIFFERENT case", async () => {
    const token = await lockCase();
    await store.updateCaseMeta("open", { password: hashCasePassword("other") });
    const result = await upgrade("/ws?caseId=open", { cookie: `${unlockCookieName("open")}=${token}` });
    expect(result.ok).toBe(false);
  });

  it("refuses a nonexistent case", async () => {
    const result = await upgrade("/ws?caseId=no-such-case");
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toMatch(/not found/i);
  });

  it("refuses an empty or missing caseId", async () => {
    expect((await upgrade("/ws?caseId=")).ok).toBe(false);
    expect((await upgrade("/ws")).ok).toBe(false);
  });

  it("refuses an untrusted origin even for an unlocked case", async () => {
    // A WebSocket handshake is NOT subject to the same-origin policy, so any page can open one.
    // The Origin header is the only signal available, and it must be checked here.
    const result = await upgrade("/ws?caseId=open", { origin: "https://evil.example" });
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toMatch(/origin/i);
  });

  it("admits the dashboard and the extension", async () => {
    expect((await upgrade("/ws?caseId=open", { origin: "http://127.0.0.1:4773" })).ok).toBe(true);
    expect((await upgrade("/ws?caseId=open", { origin: "chrome-extension://abcdefghijklmnopabcdefghijklmnop" })).ok).toBe(true);
  });

  it("refuses a case id that could escape the cases directory", async () => {
    const result = await upgrade("/ws?caseId=..%2f..%2fetc");
    expect(result.ok).toBe(false);
  });
});
