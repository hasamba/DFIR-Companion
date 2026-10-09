import { describe, it, expect } from "vitest";
import { looksLikeZeekTsv, parseZeekTsv } from "../../src/analysis/zeekTsv.js";
import { parseNetworkLogs } from "../../src/analysis/networkImport.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";

// Zeek's default (non-JSON) log writer: a `#`-header block, tab-separated rows (#2094).
// Synthetic fixture built from the standard header lines; RFC 5737 addresses only.
const tsv = (...lines: string[][]): string => lines.map((l) => l.join("\t")).join("\n");

function header(path: string, fields: string[], types: string[]): string[] {
  return [
    "#separator \\x09",
    "#set_separator\t,",
    "#empty_field\t(empty)",
    "#unset_field\t-",
    `#path\t${path}`,
    "#open\t2023-08-16-01-28-55",
    ["#fields", ...fields].join("\t"),
    ["#types", ...types].join("\t"),
  ];
}

const CONN_FIELDS = [
  "ts",
  "uid",
  "id.orig_h",
  "id.orig_p",
  "id.resp_h",
  "id.resp_p",
  "proto",
  "service",
  "duration",
  "orig_bytes",
  "resp_bytes",
  "conn_state",
  "tunnel_parents",
];
const CONN_TYPES = [
  "time",
  "string",
  "addr",
  "port",
  "addr",
  "port",
  "enum",
  "string",
  "interval",
  "count",
  "count",
  "string",
  "set[string]",
];

const CONN = [
  ...header("conn", CONN_FIELDS, CONN_TYPES),
  tsv(
    [
      "1692161622.036086",
      "C1",
      "192.0.2.10",
      "52605",
      "198.51.100.7",
      "443",
      "tcp",
      "ssl",
      "1.5",
      "100",
      "900",
      "SF",
      "(empty)",
    ],
    [
      "1692161630.000000",
      "C2",
      "192.0.2.10",
      "52606",
      "198.51.100.7",
      "443",
      "tcp",
      "ssl",
      "-",
      "200",
      "800",
      "SF",
      "(empty)",
    ],
    [
      "1692161640.000000",
      "C3",
      "192.0.2.10",
      "52607",
      "198.51.100.8",
      "22",
      "tcp",
      "-",
      "0.1",
      "5",
      "5",
      "S0",
      "-",
    ],
  ),
  "#close\t2023-08-16-02-00-00",
].join("\n");

const DNS_FIELDS = [
  "ts",
  "uid",
  "id.orig_h",
  "id.orig_p",
  "id.resp_h",
  "id.resp_p",
  "proto",
  "query",
  "qtype_name",
  "rcode_name",
  "answers",
  "TTLs",
  "rejected",
];
const DNS_TYPES = [
  "time",
  "string",
  "addr",
  "port",
  "addr",
  "port",
  "enum",
  "string",
  "string",
  "string",
  "vector[string]",
  "vector[interval]",
  "bool",
];

const DNS = [
  ...header("dns", DNS_FIELDS, DNS_TYPES),
  tsv(
    [
      "1692161622.0",
      "D1",
      "192.0.2.10",
      "5353",
      "192.0.2.1",
      "53",
      "udp",
      "evil-c2.example",
      "A",
      "NOERROR",
      "198.51.100.7,198.51.100.8",
      "60.0,60.0",
      "F",
    ],
    [
      "1692161623.0",
      "D2",
      "192.0.2.10",
      "5354",
      "192.0.2.1",
      "53",
      "udp",
      "other.example",
      "A",
      "NXDOMAIN",
      "-",
      "-",
      "T",
    ],
  ),
].join("\n");

describe("Zeek classic TSV logs (#2094)", () => {
  it("routes a TSV conn.log to the network importer", () => {
    expect(detectImportKind("conn.log", CONN)).toBe("network");
  });

  it("parses conn.log rows into Zeek flow events with the right tuple and time", () => {
    const r = parseNetworkLogs(CONN, { filename: "conn.log" });
    expect(r.total).toBe(3);
    expect(r.format).toBe("zeek");
    const https = r.events.find((e) => /:443/.test(e.description));
    expect(https?.description).toMatch(/192\.0\.2\.10/);
    expect(https?.description).toMatch(/198\.51\.100\.7/);
    expect(https?.description).toMatch(/2 connection/);
    expect(https?.timestamp).toBe(new Date(1692161622036).toISOString());
  });

  it("decodes types: unset omits the key, (empty) set is [], numbers and bools convert", () => {
    const rows = parseZeekTsv(CONN);
    expect(rows).toHaveLength(3);
    expect(rows[0]).toMatchObject({ _path: "conn", "id.resp_p": 443, duration: 1.5, tunnel_parents: [] });
    expect(rows[1]).not.toHaveProperty("duration");
    expect(rows[2]).not.toHaveProperty("service");
    const dns = parseZeekTsv(DNS);
    expect(dns[0]?.rejected).toBe(false);
    expect(dns[1]?.rejected).toBe(true);
  });

  it("splits vector fields so DNS answers and TTLs arrive as arrays", () => {
    const rows = parseZeekTsv(DNS);
    expect(rows[0]?.answers).toEqual(["198.51.100.7", "198.51.100.8"]);
    expect(rows[0]?.TTLs).toEqual([60, 60]);
    const r = parseNetworkLogs(DNS, { filename: "dns.log" });
    expect(r.total).toBe(2);
    expect(r.format).toBe("zeek");
    expect(r.iocs.some((i) => i.value === "evil-c2.example")).toBe(true);
  });

  it("re-reads the header on every block of a concatenated log", () => {
    const rows = parseZeekTsv(`${CONN}\n${DNS}`);
    expect(rows).toHaveLength(5);
    expect(rows[3]).toMatchObject({ _path: "dns", query: "evil-c2.example" });
  });

  it("decodes \\xHH escapes in string values", () => {
    const text = [...header("http", ["ts", "uri"], ["time", "string"]), "1.0\t/a\\x20b"].join("\n");
    expect(parseZeekTsv(text)[0]?.uri).toBe("/a b");
  });

  it("does not claim a plain tab-separated file", () => {
    const plain = "ts\tsrc\tdst\n1\t192.0.2.1\t192.0.2.2";
    expect(looksLikeZeekTsv(plain)).toBe(false);
    expect(looksLikeZeekTsv("#separator \\x09\nno fields here")).toBe(false);
    expect(detectImportKind("flows.tsv", plain)).not.toBe("network");
  });

  it("honours a row cap", () => {
    expect(parseZeekTsv(CONN, 2)).toHaveLength(2);
  });
});
