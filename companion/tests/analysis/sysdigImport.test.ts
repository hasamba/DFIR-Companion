import { describe, it, expect } from "vitest";
import { parseSysdig } from "../../src/analysis/sysdigImport.js";

const ndjson = (...o: unknown[]): string => o.map((x) => JSON.stringify(x)).join("\n");

describe("parseSysdig — Falco alerts (verdict-first)", () => {
  it("maps a Warning rule to Medium with MITRE from tags + proc/file IOCs", () => {
    const r = parseSysdig(ndjson({
      time: "2024-06-01T00:00:00.123456789Z",
      rule: "Terminal shell in container",
      priority: "Warning",
      output: "A shell was spawned (user=root container=nginx proc=bash 1.2.3.4)",
      hostname: "node-1",
      tags: ["container", "mitre_execution", "T1059"],
      output_fields: { "proc.name": "bash", "proc.exepath": "/bin/bash", "user.name": "root", "container.id": "abc" },
    }));
    expect(r.format).toBe("falco");
    expect(r.alerts).toBe(1);
    const e = r.events[0];
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toContain("T1059");
    expect(e.description).toContain("Falco: Terminal shell in container");
    expect(e.description).toContain("@ node-1");
    expect(e.asset).toBe("node-1");
    expect(e.processName).toBe("bash");
    expect(e.path).toBe("/bin/bash");
    expect(e.timestamp).toBe("2024-06-01T00:00:00.123Z"); // ns truncated to ms
    const iocs = r.iocs;
    expect(iocs.find((i) => i.type === "process")?.value).toBe("bash");
    expect(iocs.find((i) => i.type === "file")?.value).toBe("/bin/bash");
    expect(iocs.find((i) => i.type === "ip")?.value).toBe("1.2.3.4");
  });

  it("maps Critical priority to Critical severity", () => {
    const e = parseSysdig(ndjson({
      time: "2024-06-01T00:00:01Z", rule: "Write below etc", priority: "Critical",
      output: "File below /etc opened for writing", hostname: "h", output_fields: { "fd.name": "/etc/passwd" },
    })).events[0];
    expect(e.severity).toBe("Critical");
    expect(parseSysdig(ndjson({
      time: "t", rule: "x", priority: "Critical", output: "y", output_fields: { "fd.name": "/etc/passwd" },
    })).iocs.find((i) => i.type === "file")?.value).toBe("/etc/passwd");
  });
});

describe("parseSysdig — sysdig event output (telemetry → Info evidence)", () => {
  it("maps a sysdig -j event to an Info event reading evt.datetime, scrapes IOCs", () => {
    const r = parseSysdig(ndjson({
      "evt.num": 12345,
      "evt.datetime": "2024-06-01 00:00:00.987654321",
      "evt.cpu": 0,
      "proc.name": "curl",
      "proc.exepath": "/usr/bin/curl",
      "thread.tid": 4242,
      "evt.dir": ">",
      "evt.type": "connect",
      "evt.info": "fd=5(<4t>10.0.0.9:443) tuple=10.0.0.2:5000->10.0.0.9:443",
    }));
    expect(r.format).toBe("sysdig");
    const e = r.events[0];
    expect(e.severity).toBe("Info");
    expect(e.description).toContain("sysdig: curl > connect");
    expect(e.timestamp).toBe("2024-06-01T00:00:00.987Z");
    expect(e.sources).toEqual(["sysdig"]);
    expect(r.iocs.find((i) => i.type === "process")?.value).toBe("curl");
    expect(r.iocs.filter((i) => i.type === "ip").map((i) => i.value)).toContain("10.0.0.9");
  });

  it("reads evt.rawtime (ns epoch) when no datetime", () => {
    const e = parseSysdig(ndjson({
      "evt.num": 1, "evt.rawtime": 1717200000000000000, "proc.name": "ls", "evt.dir": "<", "evt.type": "openat",
    })).events[0];
    expect(e.timestamp).toBe("2024-06-01T00:00:00.000Z");
  });
});

describe("parseSysdig — edges", () => {
  it("a file mixing Falco + sysdig records is 'mixed'", () => {
    const r = parseSysdig(ndjson(
      { time: "2024-06-01T00:00:00Z", rule: "r", priority: "Notice", output: "o" },
      { "evt.num": 1, "evt.rawtime": 1717200000000000000, "proc.name": "ls", "evt.type": "open" },
    ));
    expect(r.format).toBe("mixed");
    expect(r.alerts).toBe(1);
    expect(r.events).toHaveLength(2);
  });

  it("ignores non-sysdig JSON", () => {
    const r = parseSysdig(ndjson({ event_id: 4624, message: "windows" }));
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });

  it("aggregates repeated identical syscalls", () => {
    const mk = (n: number): unknown => ({ "evt.num": n, "evt.rawtime": 1717200000000000000 + n, "proc.name": "nginx", "evt.dir": "<", "evt.type": "read" });
    const r = parseSysdig(ndjson(mk(1), mk(2), mk(3)));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(3);
  });
});
