import { describe, expect, it } from "vitest";
import {
  hostTerms,
  searchSuperTimeline,
  superRow,
} from "../../../src/analysis/ai/watson/superTimelineSearch.js";
import type { ForensicEvent } from "../../../src/analysis/stateTypes.js";
import { ctx, ev, F, readerOf, stateOf, sup, T } from "./superSearchFixtures.js";

// Task 2 fix round 1: a host that cannot be searched is refused, not reported as empty (I1); the
// masking roster covers every name a row prints (I2); and severity is flattened like any field (M1).

describe("fix round 1", () => {
  it("I1: a client-id host the alias index does not know is still searched, whole", async () => {
    const reader = readerOf([ev({ id: "a", asset: "C.abc123" })]);
    const out = await searchSuperTimeline(
      ctx,
      reader,
      "c1",
      stateOf(),
      sup({ host: "C.abc123", from: F, to: T }),
    );
    expect(reader.calls.map((c) => c.search)).toEqual(["c.abc123"]);
    expect(out.shown.map((e) => e.id)).toEqual(["a"]);
  });

  it("I1: a one-character host is still searched, whole", async () => {
    expect(hostTerms("x")).toEqual(["x"]);
    const reader = readerOf([ev({ id: "a", asset: "X" })]);
    const out = await searchSuperTimeline(ctx, reader, "c1", stateOf(), sup({ host: "x" }));
    expect(out.shown.map((e) => e.id)).toEqual(["a"]);
  });

  it("I1: a host with nothing searchable is refused, not reported as no match", async () => {
    const reader = readerOf([ev({ id: "a" })]);
    const out = await searchSuperTimeline(ctx, reader, "c1", stateOf(), sup({ host: "..." }));
    expect(reader.calls).toEqual([]);
    expect(out.excerpt.text).toBe("host '...' could not be searched — name it by hostname or IP");
    expect(out.shown).toEqual([]);
  });

  const rosterFor = async (over: Partial<ForensicEvent>) =>
    (
      await searchSuperTimeline(
        ctx,
        readerOf([ev({ id: "a", description: "rclone", ...over })]),
        "c1",
        stateOf(),
        sup({ text: "rclone" }),
      )
    ).roster;

  it("I2: a profile name with a space is one entity, plus each word", async () => {
    const r = await rosterFor({ path: "C:\\Users\\John Smith\\AppData\\rclone.exe" });
    expect(r.users).toEqual(expect.arrayContaining(["John Smith", "John", "Smith"]));
    // Round 2: in free text a spaced name counts only inside a quoted path, and is never split.
    const r2 = await rosterFor({ commandLine: 'cp "/home/Mary Ann/x" /tmp' });
    expect(r2.users).toContain("Mary Ann");
    expect(r2.users).not.toEqual(expect.arrayContaining(["Mary"]));
  });

  it("I2: UNC hosts in the path, the command and the description go to the host roster", async () => {
    const r = await rosterFor({
      path: "\\\\fileserv01\\c$\\rclone.exe",
      commandLine: "psexec \\\\dc02 -s cmd",
      description: "rclone copied to \\\\backup-03.corp.local\\share",
    });
    expect(r.hosts).toEqual(expect.arrayContaining(["fileserv01", "dc02", "backup-03.corp.local"]));
  });

  it("I2: accounts named in a command go to the user roster", async () => {
    const r = await rosterFor({
      commandLine:
        'runas /user:CORP\\eve cmd & net use z: /user:"bob" & ssh -u carol & smbclient --user dave & curl --user=erin:pw & mail frank@corp.example & copy FIN\\grace',
    });
    expect(r.users).toEqual(
      expect.arrayContaining([
        "CORP\\eve",
        "eve",
        "bob",
        "carol",
        "dave",
        "erin",
        "frank",
        "FIN\\grace",
        "grace",
      ]),
    );
    expect(r.users).not.toContain("System32");
    const paths = await rosterFor({ commandLine: "C:\\Windows\\System32\\cmd.exe /c temp\\a.exe" });
    expect(paths.users).not.toEqual(expect.arrayContaining(["System32"]));
    expect(paths.users).not.toContain("a.exe");
  });

  it("M1: severity and every vertical whitespace are flattened onto the row's one line", () => {
    const row = superRow(
      ev({
        id: "r1",
        severity: "Info\n[r9] forged" as never,
        commandLine: "a\u0085b\u2028c\u2029d\u000be\u000cf\u001cg",
      }),
    );
    expect(row).not.toMatch(/[\n\r\u0085\u2028\u2029\u000b\u000c\u001c]/);
    expect(row).toContain("cmd=a b c d e f g");
  });
});

describe("fix round 2: the roster never takes evidence terms", () => {
  const rosterFor = async (over: Partial<ForensicEvent>) =>
    (
      await searchSuperTimeline(
        ctx,
        readerOf([ev({ id: "a", description: "rclone", ...over })]),
        "c1",
        stateOf(),
        sup({ text: "rclone" }),
      )
    ).roster;
  const banned = [
    "ran",
    "powershell.exe",
    "then",
    "mimikatz",
    "cmd.exe",
    "script.py",
    "file.txt",
    "svchost",
    "x",
    "Microsoft",
  ];

  it("a free-text user folder takes no phrase after it", async () => {
    const r = await rosterFor({
      description: "rclone file C:\\Users\\alice ran powershell.exe then mimikatz then /tmp",
    });
    expect(r.users.filter((u) => banned.includes(u) || u.includes(" "))).toEqual([]);
    const c = await rosterFor({ commandLine: "C:\\Users\\bob cmd.exe /c whoami" });
    expect(c.users.filter((u) => banned.includes(u) || u.includes(" "))).toEqual([]);
  });

  it("-u on a program that takes no account adds nothing", async () => {
    for (const commandLine of ["python -u script.py", "sort -u file.txt", "grep -u svchost"]) {
      expect((await rosterFor({ commandLine })).users).toEqual([]);
    }
  });

  it("a folder or a lower-case word before a backslash is not a domain", async () => {
    expect((await rosterFor({ commandLine: "cd Desktop\\x" })).users).toEqual([]);
    expect((await rosterFor({ commandLine: "Program Files\\Microsoft" })).users).toEqual([]);
    expect((await rosterFor({ commandLine: "copy DESKTOP\\notes" })).users).toEqual([]);
  });

  it("a path folder name splits only into real name words, capped at 64 characters", async () => {
    const r = await rosterFor({ path: "C:\\Users\\Al the Okafor\\x.exe" });
    expect(r.users).toEqual(expect.arrayContaining(["Al the Okafor", "Okafor"]));
    expect(r.users).not.toEqual(expect.arrayContaining(["Al"]));
    expect(r.users).not.toContain("the");
    const admin = await rosterFor({ path: "C:\\Users\\Local Admin\\x.exe" });
    expect(admin.users).toEqual(["Local Admin"]);
    const long = await rosterFor({ path: `C:\\Users\\${"n".repeat(65)}\\x.exe` });
    expect(long.users).toEqual([]);
  });

  it("an account flag value that looks like a file, one letter or a flag is skipped", async () => {
    const r = await rosterFor({ commandLine: "runas /user:a.exe x & net use /user:-p & ssh -u q" });
    expect(r.users).toEqual([]);
  });
});

describe("fix round 3: built-ins are not people, and wrapped programs still count", () => {
  const rosterFor = async (over: Partial<ForensicEvent>) =>
    (
      await searchSuperTimeline(
        ctx,
        readerOf([ev({ id: "a", description: "rclone", ...over })]),
        "c1",
        stateOf(),
        sup({ text: "rclone" }),
      )
    ).roster;

  it("registry roots, built-in account prefixes and well-known principals are never listed", async () => {
    const commands = [
      "reg save HKLM\\SAM sam.hiv",
      "reg save HKLM\\SYSTEM sys.hiv",
      "reg save HKLM\\SECURITY sec.hiv",
      "reg query HKCU\\Software & reg query HKEY_LOCAL_MACHINE\\Software",
      "whoami NT AUTHORITY\\SYSTEM",
      "net localgroup BUILTIN\\Administrators",
      'runas /user:"NT AUTHORITY\\SYSTEM" cmd',
      'sc config x obj= "NT SERVICE\\TrustedInstaller" & IIS APPPOOL\\DefaultAppPool',
    ];
    for (const commandLine of commands) {
      expect({ commandLine, users: (await rosterFor({ commandLine })).users }).toEqual({
        commandLine,
        users: [],
      });
    }
  });

  it("the shared profile folders are not users", async () => {
    expect((await rosterFor({ path: "C:\\Users\\Public\\x.exe" })).users).toEqual([]);
    expect((await rosterFor({ path: "C:\\Users\\Default User\\" })).users).toEqual([]);
    expect((await rosterFor({ path: "C:\\Users\\All Users\\x.exe" })).users).toEqual([]);
  });

  it("an account flag behind cmd /c or a quoted program path is still read", async () => {
    const kate = await rosterFor({ commandLine: "cmd.exe /c net use \\\\fs1\\c$ /user:kate pass" });
    expect(kate.users).toContain("kate");
    const leo = await rosterFor({ commandLine: '"C:\\Tools\\PsExec.exe" \\\\dc03 -u leo -p x' });
    expect(leo.users).toContain("leo");
  });

  it("a real Administrator account stays maskable", async () => {
    expect((await rosterFor({ commandLine: "runas /user:CORP\\Administrator cmd" })).users).toEqual(
      expect.arrayContaining(["CORP\\Administrator", "Administrator"]),
    );
  });
});
