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

// The title (text before the first " - ") names the action the event is dated by, and the FILETIME
// zero (1601-01-01) means "never", not a date.
describe("mapSamAccount — title names the dated action", () => {
  const title = (d: string): string => d.split(" - ")[0];
  const ZERO = "1601-01-01T00:00:00Z";

  it("dates by last login and says so when the password was never set", () => {
    const e = mapSamAccount(
      account({
        ParsedF: {
          Rid: 1001,
          PasswordResetDate: ZERO,
          LastLoginDate: "2026-05-14T11:20:00Z",
          LoginCount: 4,
        },
      }),
      ARTIFACT,
      "WS01",
    );
    expect(title(e.description)).toContain("Local account: backdoor (RID 1001) — last login");
    expect(e.description).toContain("password never set");
    expect(e.description).not.toContain("1601");
    expect(e.timestamp).toContain("2026-05-14");
  });

  it("dates by the password change and says so when that is the only date", () => {
    const e = mapSamAccount(
      account({ ParsedF: { Rid: 1001, PasswordResetDate: "2026-02-01T08:00:00Z" } }),
      ARTIFACT,
      "WS01",
    );
    expect(title(e.description)).toContain("— password set");
    expect(e.timestamp).toContain("2026-02-01");
  });

  it("says 'record changed' when dated by the account key's last write", () => {
    const e = mapSamAccount(
      account({
        KeyMTime: "2026-04-01T00:00:00Z",
        ParsedF: { Rid: 1001, PasswordResetDate: "2026-02-01T08:00:00Z" },
      }),
      ARTIFACT,
      "WS01",
    );
    expect(title(e.description)).toContain("— account record changed");
    expect(e.timestamp).toContain("2026-04-01");
  });

  it("keeps 'created' as the action for a creation", () => {
    const e = mapSamAccount(account({ CreateTime: "2026-07-02T10:00:00Z" }), ARTIFACT, "WS01");
    expect(title(e.description)).toContain("Local account created: backdoor (RID 1001)");
    expect(title(e.description)).not.toContain("—");
  });

  it("says 'never logged in' for a zero last-login and does not date the event to 1601", () => {
    const e = mapSamAccount(
      account({ ParsedF: { Rid: 1001, PasswordResetDate: ZERO, LastLoginDate: ZERO } }),
      ARTIFACT,
      "WS01",
    );
    expect(e.description).toContain("never logged in");
    expect(e.description).not.toContain("1601");
    expect(e.timestamp).toBe("");
  });

  it("still dates a built-in account by its creation time, and names it", () => {
    const e = mapSamAccount(
      {
        Key: SAM_KEY,
        ParsedV: { username: "Administrator" },
        ParsedF: { Rid: 500 },
        CreateTime: "2020-01-01T00:00:00Z",
      },
      ARTIFACT,
      "WS01",
    );
    expect(e.timestamp).toContain("2020-01-01");
    expect(title(e.description)).toContain("Local account: Administrator (RID 500) — created");
    expect(e.severity).toBe("Info");
  });
});

// #2885: the description was capped AFTER the "@ HOST" suffix, so an account comment that put the
// core within a suffix-length of the 600-char cap left "… @ WS0" — and past the cap dropped the host.
describe("mapSamAccount — the host suffix survives the length cap (#2885)", () => {
  it("keeps the '@ HOST' suffix whole however long the account comment is", () => {
    for (let n = 400; n <= 650; n++) {
      const row = account({ ParsedV: { username: "backdoor", comment: "c".repeat(n) } });
      const e = mapSamAccount(row, ARTIFACT, "WS01");
      expect(e.description.length).toBeLessThanOrEqual(600);
      expect(e.description.endsWith(" @ WS01")).toBe(true);
    }
  });
});
