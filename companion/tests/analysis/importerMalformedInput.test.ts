// One shared malformed-input matrix over the structured-export text parsers (#2170). These are the
// files an analyst uploads from a tool whose output can be truncated, corrupted or attacker-shaped;
// most had only happy-path and severity tests. Every parser must survive every input below without
// throwing, return a defined result, and never pollute Object.prototype.
import { afterEach, describe, expect, it } from "vitest";
import { parseAzureStorageLog } from "../../src/analysis/azureStorageLogImport.js";
import { parseCsv } from "../../src/analysis/csvImport.js";
import { parseEmail } from "../../src/analysis/emailImport.js";
import { parseHayabusaTimeline } from "../../src/analysis/hayabusaImport.js";
import { parseJournald } from "../../src/analysis/journaldImport.js";
import { parseKapeCsv } from "../../src/analysis/kapeImport.js";
import { parseLogLines } from "../../src/analysis/logImport.js";
import { parseMacos } from "../../src/analysis/macosImport.js";
import { parseNetworkLogs } from "../../src/analysis/networkImport.js";
import { parseOktaSystemLog } from "../../src/analysis/oktaImport.js";
import { parseOsqueryLog } from "../../src/analysis/osqueryImport.js";
import { parsePlasoCsv } from "../../src/analysis/plasoImport.js";
import { parseSandboxReport } from "../../src/analysis/sandboxImport.js";
import { parseSnortLog } from "../../src/analysis/snortImport.js";
import { parseSysdig } from "../../src/analysis/sysdigImport.js";
import { parseThorReport } from "../../src/analysis/thorImport.js";
import { parseWazuhAlerts } from "../../src/analysis/wazuhImport.js";
import { parseYaraOutput } from "../../src/analysis/yaraImport.js";

type Parser = (text: string) => unknown;

const PARSERS: [string, Parser][] = [
  ["parsePlasoCsv", parsePlasoCsv],
  ["parseAzureStorageLog", parseAzureStorageLog],
  ["parseSandboxReport", parseSandboxReport],
  ["parseOsqueryLog", parseOsqueryLog],
  ["parseSnortLog", parseSnortLog],
  ["parseSysdig", parseSysdig],
  ["parseJournald", parseJournald],
  ["parseLogLines", parseLogLines],
  ["parseNetworkLogs", parseNetworkLogs],
  ["parseThorReport", parseThorReport],
  ["parseKapeCsv", parseKapeCsv],
  ["parseWazuhAlerts", parseWazuhAlerts],
  ["parseCsv", parseCsv],
  ["parseEmail", parseEmail],
  ["parseHayabusaTimeline", parseHayabusaTimeline],
  ["parseOktaSystemLog", parseOktaSystemLog],
  ["parseMacos", parseMacos],
  ["parseYaraOutput", parseYaraOutput],
];

// ~200 KB: large enough to exercise an oversized field, small enough to keep the matrix fast.
const BIG = "A".repeat(200 * 1024);

const INPUTS: [string, string][] = [
  ["empty", ""],
  ["whitespace only", "   \n\t\r\n  "],
  ["binary garbage", "\u0000\u0001\u0002�ÿ\u0080PK\u0003\u0004\u0000\u0000\u001b[31m"],
  ["truncated JSON", '{"events":[{"timestamp":"2024-01-01T00:00:00Z","rule":{"level":12'],
  ["truncated quoted CSV", 'timestamp,message\n2024-01-01,"unterminated field, with comma'],
  ["header-only CSV", "datetime,timestamp_desc,source,message\n"],
  ["double BOM", "﻿﻿timestamp,message\n2024-01-01,hello\n"],
  ["oversized field", `timestamp,message\n2024-01-01,"${BIG}"\n`],
  ["broken NDJSON", '{"a":1}\n{"b":\nnot json at all\n{"c":3}\n'],
  ["JSON null", "null"],
  ["a bare number", "42"],
  ["an array of nulls", "[null,null,null]"],
  [
    "prototype-pollution payload",
    '{"__proto__":{"polluted":"yes"},"constructor":{"prototype":{"polluted":"yes"}}}',
  ],
  ["prototype-pollution NDJSON", '{"__proto__":{"polluted":"yes"}}\n[{"__proto__":{"polluted":"yes"}}]\n'],
];

const polluted = (): unknown => (({}) as Record<string, unknown>).polluted;

afterEach(() => {
  // Defensive: a failure in one case must not leak into the next.
  delete (Object.prototype as Record<string, unknown>).polluted;
});

describe.each(PARSERS)("%s — malformed input", (_name, parse) => {
  it.each(INPUTS)("survives %s", (_label, input) => {
    let result: unknown;
    expect(() => {
      result = parse(input);
    }).not.toThrow();
    expect(result).toBeDefined();
    expect(result).not.toBeNull();
    expect(polluted()).toBeUndefined();
    const events = (result as { events?: unknown }).events;
    if (events !== undefined) expect(Array.isArray(events)).toBe(true);
  });
});
