import { describe, expect, it } from "vitest";
import {
  appendAuditEntry,
  isCapturableTab,
  originPatternMatchesUrl,
  originPatternFromUrl,
  readAuditEntries,
  requestSiteAccess,
  revokeSiteAccess,
  type PermissionGateway,
} from "../src/siteAccess.js";

function permissionGateway(result: boolean, alreadyGranted = false): PermissionGateway & {
  requested: string[][];
  removed: string[][];
} {
  const requested: string[][] = [];
  const removed: string[][] = [];
  return {
    requested,
    removed,
    contains: async () => alreadyGranted,
    request: async ({ origins }) => {
      requested.push(origins ?? []);
      return result;
    },
    remove: async ({ origins }) => {
      removed.push(origins ?? []);
      return result;
    },
  };
}

describe("site access boundaries", () => {
  it("turns an approved web page into one exact-origin permission", () => {
    expect(originPatternFromUrl("https://velo.example:8889/app/index.html#/hunts")).toBe(
      "https://velo.example:8889/*",
    );
  });

  it.each([
    "chrome://extensions",
    "about:addons",
    "moz-extension://abc/options.html",
    "file:///tmp/evidence.html",
    "data:text/plain,evidence",
    "not a URL",
  ])("refuses restricted page %s", (url) => {
    expect(originPatternFromUrl(url)).toBeNull();
  });

  it("refuses private tabs even when their URL is otherwise supported", () => {
    expect(isCapturableTab({ url: "https://velo.example/app/", incognito: true })).toBe(false);
  });

  it("matches exact and browser-wide permission changes to the current page", () => {
    expect(originPatternMatchesUrl("https://velo.example:8889/*", "https://velo.example:8889/app/")).toBe(true);
    expect(originPatternMatchesUrl("https://*/*", "https://velo.example:8889/app/")).toBe(true);
    expect(originPatternMatchesUrl("http://*/*", "https://velo.example:8889/app/")).toBe(false);
  });
});

describe("optional host permission flow", () => {
  it("requests only the current origin and reports a grant", async () => {
    const gateway = permissionGateway(true);

    const result = await requestSiteAccess("https://velo.example:8889/app/index.html", gateway);

    expect(result).toEqual({ status: "granted", origin: "https://velo.example:8889/*" });
    expect(gateway.requested).toEqual([["https://velo.example:8889/*"]]);
  });

  it("fails closed when the analyst denies access", async () => {
    const gateway = permissionGateway(false);

    const result = await requestSiteAccess("https://velo.example/app/", gateway);

    expect(result).toEqual({ status: "denied", origin: "https://velo.example/*" });
  });

  it("revokes only the selected origin", async () => {
    const gateway = permissionGateway(true);

    const result = await revokeSiteAccess("https://velo.example/app/", gateway);

    expect(result).toBe(true);
    expect(gateway.removed).toEqual([["https://velo.example/*"]]);
  });
});

describe("permission audit", () => {
  it("drops malformed stored values and keeps a bounded immutable history", () => {
    const original = [{ at: "2026-07-31T10:00:00.000Z", origin: "https://one.example/*", action: "granted" }];
    const next = appendAuditEntry(original, {
      at: "2026-07-31T10:01:00.000Z",
      origin: "https://two.example/*",
      action: "revoked",
    });

    expect(next).toHaveLength(2);
    expect(original).toHaveLength(1);
    expect(appendAuditEntry([{ nope: true }], next[1])).toEqual([next[1]]);
  });

  it("keeps only the latest 100 permission changes", () => {
    let entries: unknown = [];
    for (let i = 0; i < 105; i += 1) {
      entries = appendAuditEntry(entries, {
        at: `2026-07-31T10:${String(i).padStart(2, "0")}:00.000Z`,
        origin: `https://console-${i}.example/*`,
        action: "granted",
      });
    }
    const history = readAuditEntries(entries);
    expect(history).toHaveLength(100);
    expect(history[0].origin).toBe("https://console-5.example/*");
  });
});
