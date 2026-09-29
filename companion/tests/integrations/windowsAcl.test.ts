import { describe, it, expect } from "vitest";
import {
  aclProblem,
  parseAclOutput,
  psLiteral,
  readWindowsAcls,
  type AclRecord,
} from "../../src/integrations/mcp/windowsAcl.js";
import type { TransferRunner } from "../../src/integrations/mcp/mcpDelivery.js";

// Rights values as Windows reports them through [int]FileSystemRights.
const FULL_CONTROL = 0x1f01ff;
const MODIFY = 0x301bf;
const READ_AND_EXECUTE = 0x200a9;
const GENERIC_WRITE = 0x40000000;
const GENERIC_READ_INT32 = -2147483648; // 0x80000000 as a signed int32

const OWNER = "S-1-5-21-1000-2000-3000-1001";
const ALLOW = 0;
const DENY = 1;

const record = (a: { s: string; r: number; t: number }[], extra: Partial<AclRecord> = {}): AclRecord => ({
  path: "C:\\cases",
  owner: OWNER,
  nullDacl: false,
  entries: a.map((e) => ({ sid: e.s, rights: e.r >>> 0, allow: e.t === ALLOW })),
  ...extra,
});

describe("aclProblem — which Windows ACLs let other users write (#1863)", () => {
  it("refuses Everyone with FullControl", () => {
    expect(aclProblem(record([{ s: "S-1-1-0", r: FULL_CONTROL, t: ALLOW }]))).toMatch(/Everyone/);
  });

  it("allows BUILTIN\\Users with ReadAndExecute only", () => {
    expect(aclProblem(record([{ s: "S-1-5-32-545", r: READ_AND_EXECUTE, t: ALLOW }]))).toBeUndefined();
  });

  it("ignores Deny entries", () => {
    expect(aclProblem(record([{ s: "S-1-1-0", r: FULL_CONTROL, t: DENY }]))).toBeUndefined();
  });

  it("does not judge a SID outside the broad principals", () => {
    expect(aclProblem(record([{ s: "S-1-5-21-1-2-3-1105", r: FULL_CONTROL, t: ALLOW }]))).toBeUndefined();
  });

  it("refuses Authenticated Users with Modify", () => {
    expect(aclProblem(record([{ s: "S-1-5-11", r: MODIFY, t: ALLOW }]))).toMatch(/Authenticated Users/);
  });

  it.each([
    ["Anonymous", "S-1-5-7"],
    ["Guests", "S-1-5-32-546"],
    ["Users", "S-1-5-32-545"],
  ])("refuses %s with a single write bit", (name, sid) => {
    expect(aclProblem(record([{ s: sid, r: 0x4, t: ALLOW }]))).toMatch(new RegExp(name));
  });

  it("refuses GENERIC_WRITE and GENERIC_ALL", () => {
    expect(aclProblem(record([{ s: "S-1-1-0", r: GENERIC_WRITE, t: ALLOW }]))).toBeDefined();
    expect(aclProblem(record([{ s: "S-1-1-0", r: 0x10000000, t: ALLOW }]))).toBeDefined();
  });

  it("refuses Delete, ChangePermissions and TakeOwnership on their own", () => {
    for (const r of [0x10000, 0x40000, 0x80000, 0x40, 0x100, 0x10, 0x2]) {
      expect(aclProblem(record([{ s: "S-1-1-0", r, t: ALLOW }]))).toBeDefined();
    }
  });

  it("does not treat GENERIC_READ as write", () => {
    expect(aclProblem(record([{ s: "S-1-1-0", r: GENERIC_READ_INT32, t: ALLOW }]))).toBeUndefined();
  });

  it("refuses a null DACL (everyone has full access) but accepts an empty one", () => {
    expect(aclProblem(record([], { nullDacl: true }))).toMatch(/no access list/);
    expect(aclProblem(record([]))).toBeUndefined();
  });

  it("refuses a folder a broad principal owns", () => {
    expect(aclProblem(record([], { owner: "S-1-1-0" }))).toMatch(/owns/);
  });
});

describe("parseAclOutput", () => {
  const ok = (p: number, a: unknown[] = []) => ({ p, o: OWNER, n: false, a });

  it("reads one record per requested path, rights as unsigned", () => {
    const out = JSON.stringify([ok(0, [{ s: "S-1-1-0", r: GENERIC_READ_INT32, t: 0 }]), ok(1)]);
    const records = parseAclOutput(out, ["C:\\cases", "C:\\cases\\.mcp-delivery"]);
    expect(records.get("C:\\cases")?.entries).toEqual([{ sid: "S-1-1-0", rights: 0x80000000, allow: true }]);
    expect(records.get("C:\\cases\\.mcp-delivery")?.entries).toEqual([]);
  });

  it.each([
    ["not JSON", "Get-Acl : access denied"],
    ["not an array", JSON.stringify(ok(0))],
    ["a missing path", JSON.stringify([])],
    ["a duplicate path", JSON.stringify([ok(0), ok(0)])],
    ["an unexpected path", JSON.stringify([ok(0), ok(1)])],
    ["a path given as text, not an index", JSON.stringify([{ p: "C:\\cases", o: OWNER, n: false, a: [] }])],
    ["a missing owner", JSON.stringify([{ p: 0, n: false, a: [] }])],
    ["a missing DACL flag", JSON.stringify([{ p: 0, o: OWNER, a: [] }])],
    ["a malformed SID", JSON.stringify([ok(0, [{ s: "Everyone", r: 1, t: 0 }])])],
    ["fractional rights", JSON.stringify([ok(0, [{ s: "S-1-1-0", r: 1.5, t: 0 }])])],
    ["out-of-range rights", JSON.stringify([ok(0, [{ s: "S-1-1-0", r: 2 ** 33, t: 0 }])])],
    ["an unknown entry type", JSON.stringify([ok(0, [{ s: "S-1-1-0", r: 1, t: 7 }])])],
  ])("throws on %s", (_name, stdout) => {
    expect(() => parseAclOutput(stdout, ["C:\\cases"])).toThrow();
  });
});

describe("psLiteral", () => {
  it("doubles every PowerShell single-quote character, smart quotes included", () => {
    expect(psLiteral("C:\\it's")).toBe("'C:\\it''s'");
    expect(psLiteral("a\u2018b\u2019c\u201ad\u201be")).toBe(
      "'a\u2018\u2018b\u2019\u2019c\u201a\u201ad\u201b\u201be'",
    );
    expect(psLiteral("line\n$(calc)`;")).toBe("'line\n$(calc)`;'");
  });
});

describe("readWindowsAcls — the PowerShell call", () => {
  const decode = (args: string[]): string =>
    Buffer.from(args[args.indexOf("-EncodedCommand") + 1], "base64").toString("utf16le");

  it("runs powershell.exe without a profile, non-interactive, with one encoded script for all paths", async () => {
    const seen: { binary: string; args: string[]; timeoutMs: number }[] = [];
    const paths = ["C:\\cases", "C:\\cases\\.mcp-delivery"];
    const runner: TransferRunner = async (binary, args, opts) => {
      seen.push({ binary, args, timeoutMs: opts.timeoutMs });
      return {
        code: 0,
        stderr: "",
        stdout: JSON.stringify(paths.map((_p, i) => ({ p: i, o: OWNER, n: false, a: [] }))),
      };
    };

    const records = await readWindowsAcls(paths, runner, 12_345);

    expect(records.size).toBe(2);
    expect(seen).toHaveLength(1);
    expect(seen[0].binary).toBe("powershell.exe");
    expect(seen[0].args).toEqual(
      expect.arrayContaining(["-NoProfile", "-NonInteractive", "-EncodedCommand"]),
    );
    expect(seen[0].timeoutMs).toBe(12_345);
    const script = decode(seen[0].args);
    expect(script).toContain("$ErrorActionPreference = 'Stop'");
    expect(script).toContain("'C:\\cases\\.mcp-delivery'");
    expect(script).toContain("SecurityIdentifier");
    // No cmdlet that PowerShell autoloads from a module: under an inherited PowerShell 7
    // PSModulePath, Windows PowerShell cannot load Microsoft.PowerShell.Security, so Get-Acl fails
    // (first seen on the Windows CI runner). The script reads the descriptor through .NET instead.
    for (const cmdlet of ["Get-Acl", "New-Object", "ConvertTo-Json", "ForEach-Object"]) {
      expect(script).not.toContain(cmdlet);
    }
    expect(script).toContain("[System.Security.AccessControl.DirectorySecurity]::new(");
  });

  it("throws when PowerShell exits non-zero", async () => {
    const runner: TransferRunner = async () => ({ code: 1, stdout: "", stderr: "Get-Acl : denied" });
    await expect(readWindowsAcls(["C:\\cases"], runner, 1000)).rejects.toThrow(/exited 1.*denied/);
  });

  it("throws when PowerShell cannot be run or times out", async () => {
    const runner: TransferRunner = async () => {
      throw new Error("powershell.exe timed out after 1000ms");
    };
    await expect(readWindowsAcls(["C:\\cases"], runner, 1000)).rejects.toThrow(/timed out/);
  });
});
