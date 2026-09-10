import { describe, it, expect } from "vitest";
import {
  parsePlist,
  readLaunchJob,
  launchScope,
  classifyMacArtifact,
  isBinaryPlist,
  isXmlPlist,
  MAX_PLIST_DEPTH,
} from "../../src/analysis/macosPersistence.js";

const plist = (body: string) =>
  `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
${body}
</dict>
</plist>`;

describe("parsePlist", () => {
  it("reads strings, arrays, integers and booleans", () => {
    const p = parsePlist(
      plist(`
  <key>Label</key><string>com.example.agent</string>
  <key>ProgramArguments</key>
  <array><string>/usr/local/bin/agent</string><string>--daemon</string></array>
  <key>StartInterval</key><integer>300</integer>
  <key>RunAtLoad</key><true/>
  <key>Disabled</key><false/>`),
    );
    expect(p?.Label).toBe("com.example.agent");
    expect(p?.ProgramArguments).toEqual(["/usr/local/bin/agent", "--daemon"]);
    expect(p?.StartInterval).toBe(300);
    expect(p?.RunAtLoad).toBe(true);
    expect(p?.Disabled).toBe(false);
  });

  it("expands the five predefined XML entities and nothing else", () => {
    const p = parsePlist(
      plist("<key>Label</key><string>a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos;</string>"),
    );
    expect(p?.Label).toBe(`a & b <c> "d" 'e'`);
  });

  // An XML parser that resolves DOCTYPE entities on collected input is an XXE and a bomb in one.
  it("skips a DOCTYPE internal subset rather than reading it", () => {
    const xml = `<?xml version="1.0"?>
<!DOCTYPE plist [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<plist version="1.0"><dict><key>Label</key><string>&xxe;</string></dict></plist>`;
    const p = parsePlist(xml);
    expect(p?.Label).toBe("&xxe;");
  });

  it("reads a nested dict", () => {
    const p = parsePlist(plist("<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>"));
    expect(p?.KeepAlive).toEqual({ SuccessfulExit: false });
  });

  it("ignores comments", () => {
    const p = parsePlist(plist("<!-- a note --><key>Label</key><string>x</string>"));
    expect(p?.Label).toBe("x");
  });

  it("stops at a bounded nesting depth rather than recursing without limit", () => {
    const deep =
      "<array>".repeat(MAX_PLIST_DEPTH + 20) + "<string>x</string>" + "</array>".repeat(MAX_PLIST_DEPTH + 20);
    expect(() => parsePlist(plist(`<key>a</key>${deep}`))).not.toThrow();
  });

  it("returns null for something that is not a plist", () => {
    expect(parsePlist("hello")).toBeNull();
    expect(parsePlist("")).toBeNull();
  });

  it("recognises a binary plist without trying to read it", () => {
    expect(isBinaryPlist("bplist00  ")).toBe(true);
    expect(parsePlist("bplist00 ")).toBeNull();
    expect(isXmlPlist(plist(""))).toBe(true);
  });
});

describe("readLaunchJob", () => {
  it("takes the program from ProgramArguments when there is no Program", () => {
    const job = readLaunchJob({ ProgramArguments: ["/usr/local/bin/agent", "-q"] });
    expect(job.program).toBe("/usr/local/bin/agent");
    expect(job.arguments).toEqual(["-q"]);
    expect(job.commandLine).toBe("/usr/local/bin/agent -q");
  });

  // launchd's own rule: with Program set, ProgramArguments[0] is argv[0], not the executable.
  // Reading argv[0] as the program let a job set Program to a dropper and argv[0] to /usr/sbin/cupsd.
  it("prefers Program, and then treats ProgramArguments as the argument list", () => {
    const job = readLaunchJob({ Program: "/tmp/.x/dropper", ProgramArguments: ["/usr/sbin/cupsd", "-f"] });
    expect(job.program).toBe("/tmp/.x/dropper");
    expect(job.arguments).toEqual(["/usr/sbin/cupsd", "-f"]);
  });

  // KeepAlive is a boolean OR a dictionary of conditions. Reading a dictionary as false lost the job.
  it("treats a KeepAlive dictionary as kept alive", () => {
    expect(readLaunchJob({ KeepAlive: { SuccessfulExit: false } }).keepAlive).toBe(true);
    expect(readLaunchJob({ KeepAlive: {} }).keepAlive).toBe(false);
    expect(readLaunchJob({ KeepAlive: true }).keepAlive).toBe(true);
  });

  it("reads the scheduling and watch triggers", () => {
    const job = readLaunchJob({
      StartInterval: 60,
      StartCalendarInterval: { Hour: 3 },
      WatchPaths: ["/etc/hosts"],
      UserName: "root",
    });
    expect(job.startInterval).toBe(60);
    expect(job.scheduled).toBe(true);
    expect(job.watchPaths).toEqual(["/etc/hosts"]);
    expect(job.userName).toBe("root");
  });
});

describe("launchScope and classifyMacArtifact", () => {
  it("names what runs a plist from where it sits", () => {
    expect(launchScope("/System/Library/LaunchDaemons/com.apple.x.plist")).toBe("apple");
    expect(launchScope("/Library/LaunchDaemons/x.plist")).toBe("system-daemon");
    expect(launchScope("/Library/LaunchAgents/x.plist")).toBe("system-agent");
    expect(launchScope("/Users/alice/Library/LaunchAgents/x.plist")).toBe("user-agent");
    expect(launchScope("/tmp/x.plist")).toBe("elsewhere");
  });

  it("classifies macOS paths, falling through to the Linux classifier", () => {
    expect(classifyMacArtifact("/Library/LaunchDaemons/x.plist")).toBe("launchd");
    expect(classifyMacArtifact("/usr/lib/cron/tabs/alice")).toBe("cron");
    expect(classifyMacArtifact("/Users/alice/.zshrc")).toBe("shellrc");
    expect(classifyMacArtifact("/var/log/system.log")).toBe("unknown");
  });
});
