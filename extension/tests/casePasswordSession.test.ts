import { describe, it, expect, vi } from "vitest";
import {
  CASE_PASSWORD_SESSION_KEY,
  checkCasePassword,
  companionServerChanged,
  companionServerKey,
  forgetCaseCredential,
  forgetCredentialOnServerChange,
  isLockedRejection,
  LOCKED_PUSH_ERROR,
  lockedQueueMessage,
  pushErrorMessage,
  readCaseCredential,
  storeCaseCredential,
  type SessionArea,
} from "../src/casePasswordSession.js";

// #2135: the case password for a locked case lives in browser.storage.session ONLY — memory,
// cleared when the browser closes, never synced, never in the IndexedDB capture queue.
function memoryArea(): SessionArea & { data: Record<string, unknown> } {
  const data: Record<string, unknown> = {};
  return {
    data,
    get: async (key: string) => (key in data ? { [key]: data[key] } : {}),
    set: async (items: Record<string, unknown>) => { Object.assign(data, items); },
    remove: async (key: string) => { delete data[key]; },
  };
}

describe("case password session storage", () => {
  it("returns the stored password only for the case it belongs to", async () => {
    const area = memoryArea();
    await storeCaseCredential(area, { caseId: "c1", companionUrl: "http://a:4773", password: "pw-123456" });
    expect(await readCaseCredential(area, "c1", "http://a:4773"))
      .toEqual({ caseId: "c1", companionUrl: "http://a:4773", password: "pw-123456" });
    expect(await readCaseCredential(area, "c2", "http://a:4773")).toBeUndefined();
  });

  it("forgets the password", async () => {
    const area = memoryArea();
    await storeCaseCredential(area, { caseId: "c1", companionUrl: "http://a:4773", password: "pw-123456" });
    await forgetCaseCredential(area);
    expect(area.data[CASE_PASSWORD_SESSION_KEY]).toBeUndefined();
    expect(await readCaseCredential(area, "c1", "http://a:4773")).toBeUndefined();
  });

  it("degrades to no password when session storage is unavailable", async () => {
    expect(await readCaseCredential(undefined, "c1", "http://a:4773")).toBeUndefined();
    await expect(forgetCaseCredential(undefined)).resolves.toBeUndefined();
  });

  it("ignores a malformed stored value", async () => {
    const area = memoryArea();
    area.data[CASE_PASSWORD_SESSION_KEY] = { caseId: "c1", companionUrl: "http://a:4773", password: 42 };
    expect(await readCaseCredential(area, "c1", "http://a:4773")).toBeUndefined();
  });

  // Codex review of #2135: a password keyed by case id alone followed the analyst to another server.
  it("binds the password to the companion it was entered for", async () => {
    const area = memoryArea();
    await storeCaseCredential(area, { caseId: "c1", companionUrl: "http://a:4773/", password: "pw-123456" });
    expect(await readCaseCredential(area, "c1", "http://b:4773")).toBeUndefined();
    expect(await readCaseCredential(area, "c1", "HTTP://A:4773")).toBeDefined();
  });

  it("ignores a credential stored without a companion (written before the binding existed)", async () => {
    const area = memoryArea();
    area.data[CASE_PASSWORD_SESSION_KEY] = { caseId: "c1", password: "pw-123456" };
    expect(await readCaseCredential(area, "c1", "http://a:4773")).toBeUndefined();
  });

  it("refuses to store a password for an unparseable companion URL", async () => {
    await expect(storeCaseCredential(memoryArea(), { caseId: "c1", companionUrl: "not a url", password: "pw" }))
      .rejects.toThrow(/companion url/i);
  });
});

describe("companion server binding", () => {
  it("normalizes the companion URL to scheme, host, port and path", () => {
    expect(companionServerKey("HTTP://127.0.0.1:4773/")).toBe("http://127.0.0.1:4773");
    expect(companionServerKey("https://host.example/companion/")).toBe("https://host.example/companion");
    expect(companionServerKey("http://host:80")).toBe("http://host");
    expect(companionServerKey("not a url")).toBe("");
    expect(companionServerKey("")).toBe("");
  });

  it("detects a change of server but not a cosmetic rewrite", () => {
    expect(companionServerChanged("http://a:4773", "http://b:4773")).toBe(true);
    expect(companionServerChanged("http://a:4773", "http://a:4774")).toBe(true);
    expect(companionServerChanged("http://a:4773", "https://a:4773")).toBe(true);
    expect(companionServerChanged("http://a:4773", "http://a:4773/")).toBe(false);
    expect(companionServerChanged(undefined, undefined)).toBe(false);
  });

  it("clears the stored password when the companion URL setting changes", async () => {
    const area = memoryArea();
    await storeCaseCredential(area, { caseId: "c1", companionUrl: "http://a:4773", password: "pw-123456" });
    await forgetCredentialOnServerChange(area, {
      settings: {
        oldValue: { companionUrl: "http://a:4773", caseId: "c1" },
        newValue: { companionUrl: "http://b:4773", caseId: "c1" },
      },
    });
    expect(area.data[CASE_PASSWORD_SESSION_KEY]).toBeUndefined();
  });

  it("keeps the password when other settings change", async () => {
    const area = memoryArea();
    await storeCaseCredential(area, { caseId: "c1", companionUrl: "http://a:4773", password: "pw-123456" });
    await forgetCredentialOnServerChange(area, {
      settings: {
        oldValue: { companionUrl: "http://a:4773", running: false },
        newValue: { companionUrl: "http://a:4773", running: true },
      },
    });
    await forgetCredentialOnServerChange(area, { lastCapture: { newValue: {} } });
    expect(area.data[CASE_PASSWORD_SESSION_KEY]).toBeDefined();
  });

  it("clears the password when the settings are removed altogether", async () => {
    const area = memoryArea();
    await storeCaseCredential(area, { caseId: "c1", companionUrl: "http://a:4773", password: "pw-123456" });
    await forgetCredentialOnServerChange(area, { settings: { oldValue: { companionUrl: "http://a:4773" } } });
    expect(area.data[CASE_PASSWORD_SESSION_KEY]).toBeUndefined();
  });
});

describe("locked-case messages", () => {
  it("recognizes only the companion's locked answer", () => {
    expect(isLockedRejection(401, "locked")).toBe(true);
    expect(isLockedRejection(401, "unauthorized")).toBe(false);
    expect(isLockedRejection(403, "locked")).toBe(false);
  });

  it("counts the captures waiting for the password", () => {
    expect(lockedQueueMessage(1)).toBe("Case is locked — 1 capture waiting for the case password");
    expect(lockedQueueMessage(12)).toBe("Case is locked — 12 captures waiting for the case password");
  });

  it("tells the analyst how to recover a locked artifact push", () => {
    expect(pushErrorMessage(401, "locked", "c1", "http://x")).toBe(LOCKED_PUSH_ERROR);
    expect(LOCKED_PUSH_ERROR).toBe("Case is locked — enter the case password in the extension popup, then push again");
    expect(pushErrorMessage(429, undefined, "c1", "http://x")).toMatch(/too many wrong case passwords/i);
    expect(pushErrorMessage(0, undefined, "c1", "http://x")).toBe("Companion offline at http://x");
    expect(pushErrorMessage(404, undefined, "c1", "http://x")).toContain('Case "c1" not found');
  });
});

describe("checkCasePassword", () => {
  it("posts to the case's unlock route without credentials and reports ok on 200", async () => {
    const fetchFn = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response("{}", { status: 200 }));
    expect(await checkCasePassword(fetchFn, "http://x", "c 1", "pw-123456", "tok")).toBe("ok");
    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe("http://x/cases/c%201/unlock");
    expect(init?.credentials).toBe("omit");
    expect(JSON.parse(init?.body as string)).toEqual({ password: "pw-123456", remember: false });
    expect((init?.headers as Record<string, string>).Authorization).toBe("Bearer tok");
  });

  it.each([
    [401, "wrong"],
    [429, "locked-out"],
    [500, "error"],
  ] as const)("maps HTTP %i to %s", async (status, outcome) => {
    const fetchFn = vi.fn(async () => new Response("{}", { status }));
    expect(await checkCasePassword(fetchFn, "http://x", "c1", "pw", "")).toBe(outcome);
  });

  it("reports offline when fetch throws", async () => {
    const fetchFn = vi.fn(async () => { throw new Error("ECONNREFUSED"); });
    expect(await checkCasePassword(fetchFn, "http://x", "c1", "pw", "")).toBe("offline");
  });
});
