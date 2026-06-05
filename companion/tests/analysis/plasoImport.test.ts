import { describe, it, expect } from "vitest";
import { parsePlasoCsv } from "../../src/analysis/plasoImport.js";

function csv(header: string[], rows: string[][]): string {
  const esc = (v: string): string => (/[",\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
  return [header, ...rows].map((r) => r.map(esc).join(",")).join("\n");
}

describe("parsePlasoCsv — dynamic (psort default)", () => {
  const header = ["datetime", "timestamp_desc", "source", "source_long", "message", "parser", "display_name", "tag"];
  it("maps a dynamic row to an Info evidence event and scrapes IOCs from the message", () => {
    const text = csv(header, [[
      "2023-08-01T10:00:00.123456+00:00", "Content Modification Time", "FILE", "File entry shell item",
      "C:/Temp/evil.exe downloaded from http://evil.test/x sha256 aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899 from 203.0.113.5",
      "filestat", "TSK:/Temp/evil.exe", "-",
    ]]);
    const r = parsePlasoCsv(text);
    expect(r.format).toBe("dynamic");
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("Plaso [File entry shell item]:");
    expect(e.description).toContain("(Content Modification Time)");
    expect(e.severity).toBe("Info");
    expect(e.sources).toEqual(["Plaso"]);
    expect(e.timestamp).toBe("2023-08-01T10:00:00.123Z"); // offset → UTC, µs truncated to ms
    expect(e.path).toBe("/Temp/evil.exe");                 // TSK: prefix stripped
    const kinds = r.iocs.map((i) => i.type);
    expect(kinds).toContain("hash");
    expect(kinds).toContain("url");
    expect(kinds).toContain("ip");
    expect(kinds).toContain("file");
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("203.0.113.5");
  });

  it("does not mistake a version string for an IP", () => {
    const text = csv(header, [["2023-08-01T10:00:00+00:00", "x", "PE", "PE", "Windows build 10.0.22000 loaded", "pe", "OS:/a.dll", "-"]]);
    const r = parsePlasoCsv(text);
    expect(r.iocs.filter((i) => i.type === "ip")).toHaveLength(0);
  });
});

describe("parsePlasoCsv — l2tcsv (legacy)", () => {
  const header = ["date", "time", "timezone", "MACB", "source", "sourcetype", "type", "user", "host", "short", "desc", "version", "filename", "inode", "notes", "format", "extra"];
  it("combines MM/DD/YYYY + time + timezone and attributes the host", () => {
    const text = csv(header, [[
      "08/01/2023", "10:00:00", "UTC", "M...", "EVT", "WinEVTX", "Content Modification Time", "bob", "WS01",
      "short", "A service was installed: evil.exe", "2", "OS:/Windows/Temp/evil.exe", "12345", "-", "winevtx", "-",
    ]]);
    const r = parsePlasoCsv(text);
    expect(r.format).toBe("l2tcsv");
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("Plaso [WinEVTX]: A service was installed: evil.exe");
    expect(e.description).toContain("@ WS01");
    expect(e.asset).toBe("WS01");
    expect(e.timestamp).toBe("2023-08-01T10:00:00Z");
    expect(e.path).toBe("/Windows/Temp/evil.exe");
  });
});

describe("parsePlasoCsv — edges", () => {
  it("aggregates repetitive rows (digit runs normalized out of the key)", () => {
    const header = ["datetime", "timestamp_desc", "source", "source_long", "message", "parser", "display_name", "tag"];
    const mk = (n: number): string[] => [`2023-08-01T10:00:0${n}+00:00`, "ctime", "FILE", "File stat", `File C:/Windows/Temp/cache opened size 100${n}00 bytes`, "filestat", "OS:/Windows/Temp/cache", "-"];
    const r = parsePlasoCsv(csv(header, [mk(1), mk(2)]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
  });

  it("returns 'unknown' for a CSV that is not a psort export", () => {
    const r = parsePlasoCsv(csv(["a", "b"], [["1", "2"]]));
    expect(r.format).toBe("unknown");
    expect(r.events).toHaveLength(0);
  });
});
