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
    const r2 = await rosterFor({ commandLine: "cp /home/Mary Ann/x /tmp" });
    expect(r2.users).toEqual(expect.arrayContaining(["Mary Ann", "Mary", "Ann"]));
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
        'runas /user:CORP\\eve cmd & net use z: /user:"bob" & ssh -u carol & x --user dave & y --user=erin & mail frank@corp.example & copy FIN\\grace',
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
