import { describe, it, expect } from "vitest";
import { markJndiInjection, JNDI_INJECTION_MARKER } from "../../src/analysis/jndiInjection.js";
import { cleanDescription } from "../../src/analysis/correlate.js";
import { correlateAndSort, runTimelineChain } from "../../src/analysis/stateMerge.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

let seq = 0;
const T0 = Date.parse("2026-01-01T10:00:00Z");
const at = (ms: number) => new Date(T0 + ms).toISOString();
const ev = (over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id: `e${++seq}`,
  timestamp: at(0),
  description: "",
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "web-01",
  ...over,
});

const lookup = (over: Partial<ForensicEvent> = {}) =>
  ev({
    description: "java outbound connection",
    processName: "java",
    pid: 100,
    action: "network_send",
    dstIp: "203.0.113.5",
    port: 1389,
    severity: "Low",
    ...over,
  });
const classFetch = (over: Partial<ForensicEvent> = {}) => lookup({ port: 8888, timestamp: at(300), ...over });
const shell = (over: Partial<ForensicEvent> = {}) =>
  ev({
    description: "Process create: bash",
    processName: "bash",
    parentName: "java",
    pid: 200,
    commandLine: "bash -c echo YmFzaCAtaQ==|base64 -d|bash",
    timestamp: at(800),
    ...over,
  });

const byId = (events: ForensicEvent[], id: string) => events.find((e) => e.id === id)!;

describe("markJndiInjection — fires on the Log4Shell shape", () => {
  it("raises the LDAP lookup and the JVM's shell child to High with T1190 + T1203", () => {
    const l = lookup();
    const c = classFetch();
    const s = shell();
    const out = markJndiInjection([l, c, s]);
    for (const id of [l.id, s.id]) {
      const e = byId(out, id);
      expect(e.severity).toBe("High");
      expect(e.mitreTechniques).toEqual(expect.arrayContaining(["T1190", "T1203"]));
      expect(e.description).toContain("Log4Shell shape (CVE-2021-44228)");
      expect(e.description).toContain(JNDI_INJECTION_MARKER);
      expect(e.description).toContain("203.0.113.5:8888");
    }
    // The class-fetch row is corroboration, not a leg — it is left as it was.
    expect(byId(out, c.id)).toBe(c);
  });

  it("fires for a PRIVATE destination on a non-standard LDAP/RMI port (lab / insider attacker host)", () => {
    // The OTRF Log4Shell lab's attacker LDAP server is 192.168.2.6:1389. Nothing ordinary listens
    // there, so the destination's reach is not required for 1389/1099/1098.
    const l = lookup({ dstIp: "192.168.2.6" });
    const s = shell();
    const out = markJndiInjection([l, s]);
    expect(byId(out, l.id).severity).toBe("High");
    expect(byId(out, s.id).severity).toBe("High");
  });

  it("reads Sysmon rows whose fields live only in the description, and an <unknown process> child", () => {
    const l = ev({
      description:
        "Sysmon Network connection (EID 3) - Image=/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java - DestinationIp=192.168.2.6 - DestinationPort=1389 - Protocol=tcp @ UBUNTU5",
      severity: "Low",
      asset: "UBUNTU5",
    });
    const s = ev({
      description:
        "Sysmon Process create (EID 1) - Image=<unknown process> - CommandLine=bash -c {echo,YmFz}|{base64,-d}|{bash,-i}",
      processName: "<unknown process>",
      parentName: "java",
      commandLine: "bash -c {echo,YmFz}|{base64,-d}|{bash,-i}",
      asset: "UBUNTU5",
      timestamp: at(230),
    });
    const out = markJndiInjection([l, s]);
    expect(byId(out, l.id).severity).toBe("High");
    expect(byId(out, s.id).severity).toBe("High");
    expect(byId(out, s.id).description).toContain("spawned bash");
  });
});

describe("markJndiInjection — does not fire", () => {
  it("with no shell spawn", () => {
    const events = [lookup(), classFetch()];
    expect(markJndiInjection(events)).toBe(events);
  });

  it("when the shell comes outside the window, or before the lookup", () => {
    const late = [lookup(), shell({ timestamp: at(61_000) })];
    expect(markJndiInjection(late)).toBe(late);
    const early = [lookup({ timestamp: at(5_000) }), shell({ timestamp: at(0) })];
    expect(markJndiInjection(early)).toBe(early);
  });

  it("for a non-JVM parent", () => {
    const events = [lookup({ processName: "python3" }), shell({ parentName: "python3" })];
    expect(markJndiInjection(events)).toBe(events);
  });

  it("for an ordinary directory bind: port 389/636 to a private address", () => {
    const events = [lookup({ dstIp: "10.0.0.5", port: 389 }), shell()];
    expect(markJndiInjection(events)).toBe(events);
    const ldaps = [lookup({ dstIp: "10.0.0.5", port: 636 }), shell()];
    expect(markJndiInjection(ldaps)).toBe(ldaps);
  });

  it("for a loopback RMI registry (local JMX)", () => {
    const events = [lookup({ dstIp: "127.0.0.1", port: 1099 }), shell()];
    expect(markJndiInjection(events)).toBe(events);
  });

  it("across hosts", () => {
    const events = [lookup(), shell({ asset: "web-02" })];
    expect(markJndiInjection(events)).toBe(events);
  });

  it("for a JVM child that is not a shell or downloader", () => {
    const events = [lookup(), shell({ processName: "jstat", commandLine: "jstat -gc 100" })];
    expect(markJndiInjection(events)).toBe(events);
  });
});

describe("markJndiInjection — only raises, once", () => {
  it("never lowers a Critical and is idempotent", () => {
    const l = lookup({ port: 389, dstIp: "198.51.100.7", severity: "Critical" });
    const s = shell();
    const once = markJndiInjection([l, s]);
    expect(byId(once, l.id).severity).toBe("Critical");
    const twice = markJndiInjection(once);
    expect(twice).toBe(once);
    const notes = byId(twice, s.id).description.split(JNDI_INJECTION_MARKER).length - 1;
    expect(notes).toBe(1);
  });

  it("does not mutate its input", () => {
    const l = lookup();
    const s = shell();
    markJndiInjection([l, s]);
    expect(l.severity).toBe("Low");
    expect(s.description).toBe("Process create: bash");
  });

  it("strips its note before correlate takes a duplicate key", () => {
    const [, s] = markJndiInjection([lookup(), shell()]);
    expect(cleanDescription(s.description)).toBe("Process create: bash");
  });
});

describe("markJndiInjection — wired into the merge chain", () => {
  it("survives runTimelineChain and correlate does not fold the two legs together", () => {
    const l = lookup();
    const s = shell();
    const { events: sorted } = correlateAndSort(runTimelineChain([l, s], [], at(0)));
    const marked = sorted.filter((e) => e.description.includes(JNDI_INJECTION_MARKER));
    expect(marked).toHaveLength(2);
    expect(marked.every((e) => e.severity === "High")).toBe(true);
  });
});
