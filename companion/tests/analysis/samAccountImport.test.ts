// Windows.Forensics.SAM — isSamAccountRow / mapSamAccount direct tests (#2170). Graded on the RID;
// "created" only with a real creation timestamp; hash columns never rendered.
import { describe, expect, it } from "vitest";
import { isSamAccountRow, mapSamAccount } from "../../src/analysis/samAccountImport.js";

const ARTIFACT = "Windows.Forensics.SAM";
const SAM_KEY = "C:\\Windows\\System32\\config\\SAM\\SAM\\Domains\\Account\\Users\\000003E9";

const account = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  Key: SAM_KEY,
  ParsedV: { username: "backdoor", fullname: "Backup Operator", ntpwd_hash: "deadbeefdeadbeef" },
  ParsedF: { Rid: 1001, Flags: 0x0200, LoginCount: 3 },
  ...over,
});

describe("isSamAccountRow", () => {
  it("is true for a row carrying ParsedV and a SAM key", () => {
    expect(isSamAccountRow(account())).toBe(true);
  });

  it("is true for ParsedV alone (the container is unique to the SAM artifact)", () => {
    expect(isSamAccountRow({ ParsedV: {} })).toBe(true);
  });

  it("is true for ParsedF with a SAM hive path", () => {
    expect(isSamAccountRow({ ParsedF: {}, OSPath: SAM_KEY })).toBe(true);
  });

  it("is false for ParsedF with no SAM path", () => {
    expect(isSamAccountRow({ ParsedF: {}, OSPath: "C:\\temp\\x" })).toBe(false);
  });

  it.each([
    ["a plain row", { Name: "x", OSPath: SAM_KEY }],
    ["an empty row", {}],
  ])("is false for %s", (_name, r) => {
    expect(isSamAccountRow(r)).toBe(false);
  });
});

describe("mapSamAccount — happy path", () => {
  it("describes a custom account as Low with its user, RID, flags and host, and never the hash", () => {
    const e = mapSamAccount(account(), ARTIFACT, "WS01");
    expect(e.severity).toBe("Low");
    expect(e.mitre).toEqual([]);
    expect(e.description).toContain(`Velociraptor [${ARTIFACT}]: Local account: backdoor (RID 1001)`);
    expect(e.description).toContain('"Backup Operator"');
    expect(e.description).toContain("[password never expires]");
    expect(e.description).toContain("3 logins");
    expect(e.description).not.toContain("deadbeef");
    expect(e.asset).toBe("WS01");
    expect(e.aggKey).toBe("vr|sam|ws01|backdoor|1001");
  });

  it("calls a custom account with a creation time a creation (Medium, T1136.001)", () => {
    const e = mapSamAccount(account({ CreateTime: "2026-07-02T10:00:00Z" }), ARTIFACT, "WS01");
    expect(e.severity).toBe("Medium");
    expect(e.mitre).toEqual(["T1136.001"]);
    expect(e.description).toContain("Local account created: backdoor");
    expect(e.timestamp).toContain("2026-07-02");
  });

  it("grades a built-in account (RID < 1000) Info", () => {
    const e = mapSamAccount(
      { Key: SAM_KEY, ParsedV: { username: "Administrator" }, ParsedF: { Rid: 500 } },
      ARTIFACT,
      "WS01",
    );
    expect(e.severity).toBe("Info");
  });

  it("reads the RID from the hex key name when ParsedF carries none", () => {
    const e = mapSamAccount({ Name: "000003E9", ParsedV: { username: "u" } }, ARTIFACT, "H");
    expect(e.description).toContain("(RID 1001)");
  });
});

describe("mapSamAccount — malformed rows", () => {
  it("does not throw on { ParsedV: {} } and falls back to a placeholder account at Info", () => {
    const e = mapSamAccount({ ParsedV: {} }, ARTIFACT, "");
    expect(e.severity).toBe("Info");
    expect(e.description).toContain("Local account: (account)");
    expect(e.aggKey).toBe("vr|sam||(account)|?");
    expect(e.asset).toBeUndefined();
    expect(e.timestamp).toBe("");
  });

  it.each([
    ["ParsedF as a string", { ParsedV: { username: "u" }, ParsedF: "garbage" }],
    ["a non-numeric RID", { ParsedV: { username: "u" }, ParsedF: { Rid: "abc" } }],
    [
      "Flags as an array of strings",
      { ParsedV: { username: "u" }, ParsedF: { Rid: 1001, Flags: ["ACCOUNT_DISABLED"] } },
    ],
    ["an empty row", {}],
  ])("does not throw on %s", (_name, r) => {
    const e = mapSamAccount(r, ARTIFACT, "H");
    expect(typeof e.description).toBe("string");
    expect(["Info", "Low", "Medium"]).toContain(e.severity);
  });
});
