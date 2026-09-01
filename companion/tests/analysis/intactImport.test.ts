import { describe, it, expect } from "vitest";
import {
  looksLikeIntactPrefix,
  INTACT_PLUGIN_ROW_CAP,
  INTACT_YARA_ROW_CAP,
  isIntactMemoryFile,
  normalizeVolatilityPluginKey,
  parseIntact,
  parseMemoryOrIntact,
} from "../../src/analysis/intactImport.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";

// ── fixtures ──────────────────────────────────────────────────────────────────
//
// Shapes taken from real Intact output (a VolWeb run trimmed into two files). Plugin keys are the
// FULLY QUALIFIED Volatility 3 class ids Intact emits, the plugin rows carry no `__children`
// (Intact flattens the TreeGrid away), and the YARA rows are `{Offset, Rule, Component, Value}`.

function psTreeRows(): object[] {
  return [
    {
      Cmd: "wininit.exe",
      PID: 684,
      PPID: 588,
      Path: "C:\\WINDOWS\\system32\\wininit.exe",
      Threads: 1,
      "Offset(V)": 213901691167040,
      CreateTime: "2026-08-30T15:00:34+00:00",
      ImageFileName: "wininit.exe",
    },
    {
      Cmd: "services.exe",
      PID: 832,
      PPID: 684,
      Path: "C:\\WINDOWS\\system32\\services.exe",
      Threads: 8,
      "Offset(V)": 213901691334784,
      CreateTime: "2026-08-30T15:00:35+00:00",
      ImageFileName: "services.exe",
    },
    {
      Cmd: "svchost.exe -k netsvcs",
      PID: 1944,
      PPID: 832,
      Path: "C:\\WINDOWS\\system32\\svchost.exe",
      Threads: 12,
      "Offset(V)": 213901691444608,
      CreateTime: "2026-08-30T15:00:37+00:00",
      ImageFileName: "svchost.exe",
    },
  ];
}

// Two benign RWX regions from the real sample: Defender's scanning emulator, and an interactive
// PowerShell console with the .NET JIT loaded.
function malfindRows(): object[] {
  return [
    {
      PID: 10884,
      Tag: "VadS",
      Process: "powershell.exe",
      "Start VPN": 2178332819456,
      Protection: "PAGE_EXECUTE_READWRITE",
      PrivateMemory: 1,
    },
    {
      PID: 10268,
      Tag: "VadS",
      Process: "MsMpEng.exe",
      "Start VPN": 2178563471360,
      Protection: "PAGE_EXECUTE_READWRITE",
      PrivateMemory: 1,
    },
  ];
}

function svcRows(n: number): object[] {
  return Array.from({ length: n }, (_, i) => ({
    Dll: "-",
    PID: 2008,
    Name: `Service${i}`,
    Order: i,
    Start: "SERVICE_AUTO_START",
    State: "SERVICE_RUNNING",
    Binary: `C:\\Windows\\System32\\svc${i}.exe`,
    Offset: 2411206176288 + i,
    Display: `Service ${i}`,
  }));
}

function yaraRow(offset: number, rule: string, component = "$s0", value = "b'x'"): object {
  return { Offset: offset, Rule: rule, Component: component, Value: value };
}

// Hits far enough apart that the rule-file cluster guard never fires.
function scatteredYara(): { Offset: number; Rule: string; Component: string; Value: string }[] {
  return [
    { Offset: 0x1000_0000, Rule: "Cobalt_Strike_Beacon", Component: "$s1", Value: "b'beacon.dll'" },
    { Offset: 0x2000_0000, Rule: "Mimikatz_Memory", Component: "$s2", Value: "b'sekurlsa'" },
  ];
}

function payload(extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    plugins: {
      "volatility3.plugins.windows.pstree.PsTree": psTreeRows(),
      "volatility3.plugins.windows.malfind.Malfind": malfindRows(),
      "volatility3.plugins.windows.svcscan.SvcScan": svcRows(3),
      "volatility3.plugins.windows.registry.userassist.UserAssist": [
        { Name: "N/A", Path: "ntuser.dat\\Software\\Microsoft\\Windows", Type: "Key" },
      ],
      ...(extra.plugins as object | undefined),
    },
    yara: extra.yara ?? scatteredYara().map((r) => ({ Offset: r.Offset, Rule: r.Rule })),
  });
}

function jsonl(rows: object[]): string {
  return rows.map((r) => JSON.stringify(r)).join("\n");
}

// ── detection ─────────────────────────────────────────────────────────────────

describe("Intact detection", () => {
  it("routes the wrapped memory payload to the memory importer, not the AI log fallback", () => {
    expect(detectImportKind("memory_payload.json", payload())).toBe("memory");
  });

  it("routes the YARA JSON-Lines file to the memory importer, not the AI log fallback", () => {
    expect(detectImportKind("yarascan_results.jsonl", jsonl(scatteredYara()))).toBe("memory");
  });

  // POST /cases/:id/import-file sniffs a bounded 256 KB HEAD of the file, never the whole thing —
  // a Plaso super-timeline cannot even be held as one string. A real memory_payload.json is 289 KB,
  // so the sample holds no complete root object, jsonSample returns nothing, and every structural
  // signature is skipped. The route answered 400 for the very file this importer was written for.
  it("recognises the wrapper from a truncated head, which is all the file-path route sniffs", () => {
    const head = payload().slice(0, 120);
    expect(() => JSON.parse(head)).toThrow(); // no complete root object to parse
    expect(detectImportKind("memory_payload.json", head)).toBe("memory");
  });

  // The same case at the route's real bound, so this keeps pinning production behaviour if the
  // 120-character slice above ever stops being representative.
  it("recognises a payload larger than the route's own 256 KB sniff sample", () => {
    const big = payload({
      plugins: { "volatility3.plugins.windows.svcscan.SvcScan": svcRows(INTACT_PLUGIN_ROW_CAP * 8) },
    });
    expect(big.length).toBeGreaterThan(1 << 18);
    const head = Buffer.from(big, "utf8")
      .subarray(0, 1 << 18)
      .toString("utf8"); // exactly what POST /cases/:id/import-file reads
    expect(detectImportKind("memory_payload.json", head)).toBe("memory");
  });

  // The prefix sniff is a FALLBACK for a file too big to parse, and it must never outrank a file the
  // structural signatures can classify properly. Two loose fragments — a `plugins` object of any
  // shape, and an os-dotted key anywhere else in the document — used to be enough to claim a file
  // that parses perfectly well. Claiming it routes it to the memory importer, which finds no Intact
  // payload and emits ZERO events: the whole file is accepted and silently dropped.
  it("leaves a parseable file alone even when it carries both fragments in unrelated places", () => {
    const siem = JSON.stringify({
      "@timestamp": "2026-09-01T10:00:00Z",
      message: "sysmon agent started",
      host: { name: "srv1" },
      plugins: { sysmon: "enabled", winlogbeat: "enabled" },
      "windows.eventlog": ["Security", "System"],
    });
    expect(detectImportKind("agent.json", siem)).toBe("siem");

    const sandbox = JSON.stringify({
      info: { id: 1 },
      signatures: [{ name: "x" }],
      plugins: { processing: ["static"] },
      "linux.behaviour": [{ call: "open" }],
    });
    expect(detectImportKind("report.json", sandbox)).toBe("sandbox");
  });

  it("requires the plugin id to sit INSIDE the plugins object, not merely somewhere in the file", () => {
    const split = `{"plugins":{"sysmon":"on"},"note":"windows.pslist":[]}`;
    expect(looksLikeIntactPrefix(split)).toBe(false);
    expect(looksLikeIntactPrefix(payload())).toBe(true);
  });

  // The two constraints this sniff has to satisfy AT ONCE, so neither can be traded for the other.
  //
  // A truncated payload can still yield a sample: cut a row-per-line serialisation mid-file and
  // jsonSample finds one complete row on a line. A `{Name, Offset}` mutantscan row matches no
  // Volatility column fingerprint, so the structural path lands on the SIEM catch-all — and a sniff
  // placed BELOW that path never gets to correct it. Hence the sniff runs ahead of the structural
  // checks. What makes that safe is the PATTERN, not the position: it matches `plugins` immediately
  // followed by a Volatility plugin id, which nothing but Intact's wrapper has.
  it("claims a truncated payload whichever way it was serialised", () => {
    const rows = Array.from({ length: 4000 }, (_, i) => ({ Name: `Mutant_${i}`, Offset: 60559664 + i }));
    const body = { plugins: { "volatility3.plugins.windows.mutantscan.MutantScan": rows } };
    const cut = (text: string): string =>
      Buffer.from(text, "utf8")
        .subarray(0, 1 << 18)
        .toString("utf8");

    expect(detectImportKind("memory_payload.json", cut(JSON.stringify(body)))).toBe("memory");
    expect(detectImportKind("memory_payload.json", cut(JSON.stringify(body, null, 2)))).toBe("memory");
    // Row-per-line: jsonSample DOES find a sample here, and it is not a recognisable Volatility row.
    const perRow =
      '{\n "plugins": {\n  "volatility3.plugins.windows.mutantscan.MutantScan": [\n' +
      rows.map((r) => `   ${JSON.stringify(r)}`).join(",\n");
    expect(detectImportKind("memory_payload.json", cut(perRow))).toBe("memory");
  });

  it("does not claim a truncated head that is not Intact's wrapper", () => {
    const plain = JSON.stringify({ "windows.pslist.PsList": psTreeRows() }).slice(0, 120);
    expect(detectImportKind("whatever.json", plain)).not.toBe("memory");
    const wrapped = JSON.stringify({ plugins: { "Windows.KapeFiles.Targets": [{ a: 1 }] } }).slice(0, 60);
    expect(detectImportKind("velo.json", wrapped)).not.toBe("memory");
  });

  it("claims neither a plain Volatility plugin map nor an unrelated NDJSON record", () => {
    expect(isIntactMemoryFile({ "windows.pslist.PsList": [] }, null)).toBe(false);
    expect(isIntactMemoryFile({ Offset: 1, Rule: "R", Extra: 2 }, { Offset: 1, Rule: "R", Extra: 2 })).toBe(
      false,
    );
  });
});

// ── plugin-key normalisation ──────────────────────────────────────────────────

describe("normalizeVolatilityPluginKey", () => {
  it("reduces a fully qualified class id to the os.module form the classifier expects", () => {
    expect(normalizeVolatilityPluginKey("volatility3.plugins.windows.pstree.PsTree")).toBe("windows.pstree");
    expect(normalizeVolatilityPluginKey("volatility3.plugins.windows.malfind.Malfind")).toBe(
      "windows.malfind",
    );
  });

  it("keeps the leaf module of a nested plugin namespace", () => {
    expect(normalizeVolatilityPluginKey("volatility3.plugins.windows.registry.userassist.UserAssist")).toBe(
      "windows.userassist",
    );
  });

  it("leaves an already-plain key alone", () => {
    expect(normalizeVolatilityPluginKey("windows.pslist")).toBe("windows.pslist");
  });
});

// ── plugin tables ─────────────────────────────────────────────────────────────

describe("Intact plugin tables", () => {
  it("parses every plugin in the wrapper into its own table", () => {
    const r = parseIntact(payload(), {});
    expect(r).not.toBeNull();
    expect(r!.tables).toBe(4);
    expect(r!.format).toBe("intact-volweb");
  });

  it("keeps the process tree's parent to child links", () => {
    const r = parseIntact(payload(), {})!;
    const svchost = r.events.find((e) => /pstree.*svchost\.exe/.test(e.description));
    expect(svchost?.parentName).toBe("services.exe");
    expect(svchost?.description).toContain("PPID 832");
  });

  it("tags malfind rows for process injection", () => {
    const r = parseIntact(payload(), {})!;
    const malfind = r.events.filter((e) => e.mitreTechniques.includes("T1055"));
    expect(malfind).toHaveLength(2);
    expect(r.injected).toBe(2);
  });

  it("surfaces a benign RWX region without asserting an injection happened", () => {
    const r = parseIntact(payload(), {})!;
    const defender = r.events.find((e) => /MsMpEng\.exe/.test(e.description))!;
    expect(defender.description).toContain("executable/injected private memory");
    expect(defender.description).toContain("PAGE_EXECUTE_READWRITE");
    expect(defender.description).not.toMatch(/\binjected code\b|\bconfirmed\b/i);
  });

  it("marks every event as coming from Intact", () => {
    const r = parseIntact(payload(), {})!;
    expect(r.events.every((e) => e.sources?.includes("Intact"))).toBe(true);
  });
});

// ── YARA rows ─────────────────────────────────────────────────────────────────

describe("Intact YARA rows", () => {
  it("parses the JSON-Lines file on its own", () => {
    const r = parseIntact(jsonl(scatteredYara()), {})!;
    expect(r.format).toBe("intact-yara");
    expect(r.yaraHits).toBe(2);
    expect(r.events).toHaveLength(2);
  });

  it("grades a memory-resident hit Low, below the file-based YARA default", () => {
    const r = parseIntact(jsonl(scatteredYara()), {})!;
    expect(r.events.map((e) => e.severity)).toEqual(["Low", "Low"]);
  });

  it("carries the matched string component and value into the description", () => {
    const r = parseIntact(jsonl(scatteredYara()), {})!;
    const beacon = r.events.find((e) => e.description.includes("Cobalt_Strike_Beacon"))!;
    expect(beacon.description).toContain("$s1");
    expect(beacon.description).toContain("beacon.dll");
    expect(beacon.description).toContain("0x10000000");
  });

  it("mints no IOCs — a rule name matched in RAM names no file and no hash", () => {
    const r = parseIntact(jsonl(scatteredYara()), {})!;
    expect(r.iocs).toEqual([]);
  });

  // A file holding exactly ONE hit is a complete JSON object, not JSON Lines — it parsed as an
  // object, matched neither the payload wrapper nor an array, and fell through to the ordinary
  // memory importer, which produced nothing. A one-hit scan is exactly the case that matters most.
  it("reads a file holding exactly one hit", () => {
    const r = parseIntact(jsonl([yaraRow(0x1000_0000, "Cobalt_Strike_Beacon", "$s1", "b'beacon.dll'")]), {})!;
    expect(r).not.toBeNull();
    expect(r.format).toBe("intact-yara");
    expect(r.yaraHits).toBe(1);
    expect(r.events[0].description).toContain("Cobalt_Strike_Beacon");
  });

  it("still routes that one-hit file through the dispatcher, not the plain memory importer", () => {
    const one = jsonl([yaraRow(0x1000_0000, "Cobalt_Strike_Beacon")]);
    expect(detectImportKind("yarascan_results.jsonl", one)).toBe("memory");
    expect(parseMemoryOrIntact(one, {}).events).toHaveLength(1);
  });

  it("collapses two string matches of one rule at one offset into a single hit", () => {
    const rows = [
      yaraRow(0x1000_0000, "WinX_Shell_html", "$s0", "b'WinX Shell'"),
      yaraRow(0x1000_0000, "WinX_Shell_html", "$s1", "b'Created by greenwood'"),
    ];
    const r = parseIntact(jsonl(rows), {})!;
    expect(r.yaraHits).toBe(1);
    expect(r.events).toHaveLength(1);
  });
});

// ── the two YARA sets overlap ─────────────────────────────────────────────────

describe("Intact YARA dedupe across the two files", () => {
  it("mints the same event id for one (Offset, Rule) whichever file it came from", () => {
    const shared = scatteredYara();
    const fromPayload = parseIntact(
      payload({ yara: shared.map((r) => ({ Offset: r.Offset, Rule: r.Rule })) }),
      {},
    )!;
    const fromJsonl = parseIntact(jsonl(shared), {})!;
    const idsA = fromPayload.events.filter((e) => e.id).map((e) => e.id);
    const idsB = fromJsonl.events.map((e) => e.id);
    expect(idsA.length).toBe(2);
    expect(new Set(idsA)).toEqual(new Set(idsB));
  });

  // mergeDelta overwrites `description` unconditionally but only sets `message` when the incoming
  // event HAS one. The matched string therefore has to live in `message` as well, or importing the
  // stripped payload after the full JSON-Lines file would delete the detail from the case.
  it("carries the matched detail in `message`, which a later sparse import cannot clear", () => {
    const rich = parseIntact(jsonl(scatteredYara()), {})!;
    const beacon = rich.events.find((e) => e.description.includes("Cobalt_Strike_Beacon"))!;
    expect(beacon.message).toContain("$s1");
    expect(beacon.message).toContain("beacon.dll");

    const sparse = parseIntact(
      payload({ yara: scatteredYara().map((r) => ({ Offset: r.Offset, Rule: r.Rule })) }),
      {},
    )!;
    const sparseBeacon = sparse.events.find((e) => e.description.includes("Cobalt_Strike_Beacon"))!;
    expect(sparseBeacon.id).toBe(beacon.id); // same row…
    expect(sparseBeacon.message).toBeUndefined(); // …and it carries nothing that could overwrite it
  });

  it("keeps every string match of one hit in `message`, untruncated", () => {
    const rows = [
      yaraRow(0x1000_0000, "WinX_Shell_html", "$s0", "b'WinX Shell'"),
      yaraRow(0x1000_0000, "WinX_Shell_html", "$s1", "b'Created by greenwood from n57'"),
    ];
    const r = parseIntact(jsonl(rows), {})!;
    expect(r.events[0].message).toContain("WinX Shell");
    expect(r.events[0].message).toContain("Created by greenwood from n57");
  });

  it("gives two different (Offset, Rule) pairs two different ids", () => {
    const r = parseIntact(jsonl(scatteredYara()), {})!;
    expect(new Set(r.events.map((e) => e.id)).size).toBe(2);
  });

  it("leaves the plugin events without a stable id, so the import prefix still numbers them", () => {
    const r = parseIntact(payload({ yara: [] }), {})!;
    expect(r.events.every((e) => e.id === "")).toBe(true);
  });
});

// ── the rule-file cluster guard ───────────────────────────────────────────────

describe("Intact YARA rule-file cluster guard", () => {
  // A YARA rule set resident in RAM matches ITSELF: many distinct rules inside a few kilobytes.
  function ruleFileCluster(): object[] {
    const base = 0x980c_a715_6462;
    return Array.from({ length: 10 }, (_, i) => yaraRow(base + i * 1400, `WebShell_Rule_${i}`, "$s0"));
  }

  it("demotes a dense many-rule cluster to Info", () => {
    const r = parseIntact(jsonl(ruleFileCluster()), {})!;
    expect(r.events.every((e) => e.severity === "Info")).toBe(true);
    expect(r.events[0].description).toContain("rule set resident in memory");
  });

  it("leaves hits scattered across the address space at Low", () => {
    const spread = Array.from({ length: 10 }, (_, i) => yaraRow(0x1000_0000 + i * 0x100_0000, `Rule_${i}`));
    const r = parseIntact(jsonl(spread), {})!;
    expect(r.events.every((e) => e.severity === "Low")).toBe(true);
  });

  it("leaves many hits of ONE rule in a small span alone — that is one region, not a rule file", () => {
    const same = Array.from({ length: 10 }, (_, i) => yaraRow(0x1000_0000 + i * 64, "Cobalt_Strike_Beacon"));
    const r = parseIntact(jsonl(same), {})!;
    expect(r.events.every((e) => e.severity === "Low")).toBe(true);
  });
});

// ── truncation disclosure ─────────────────────────────────────────────────────

describe("Intact row caps", () => {
  it("names every table that hit Intact's row cap", () => {
    const r = parseIntact(
      payload({
        plugins: { "volatility3.plugins.windows.svcscan.SvcScan": svcRows(INTACT_PLUGIN_ROW_CAP) },
        yara: Array.from({ length: INTACT_YARA_ROW_CAP }, (_, i) => ({
          Offset: 0x1000_0000 + i * 0x10_0000,
          Rule: `Rule_${i}`,
        })),
      }),
      {},
    )!;
    expect(r.truncated.map((t) => t.name)).toEqual(["svcscan", "yara"]);
    expect(r.truncated.map((t) => t.rows)).toEqual([INTACT_PLUGIN_ROW_CAP, INTACT_YARA_ROW_CAP]);
  });

  it("reports nothing when no table reached the cap", () => {
    expect(parseIntact(payload(), {})!.truncated).toEqual([]);
  });

  it("never calls the standalone JSON-Lines file truncated — it carries the full set", () => {
    const many = Array.from({ length: INTACT_YARA_ROW_CAP * 2 }, (_, i) =>
      yaraRow(0x1000_0000 + i * 0x10_0000, `Rule_${i}`),
    );
    expect(parseIntact(jsonl(many), {})!.truncated).toEqual([]);
  });
});

// ── dispatch ──────────────────────────────────────────────────────────────────

describe("parseMemoryOrIntact", () => {
  it("hands an Intact payload to the Intact path", () => {
    expect(parseMemoryOrIntact(payload(), {}).format).toBe("intact-volweb");
  });

  it("leaves a plain Volatility plugin map on the existing path", () => {
    const plain = JSON.stringify({ "windows.pslist.PsList": psTreeRows() });
    expect(parseMemoryOrIntact(plain, {}).format).toBe("volatility-map");
  });

  it("returns null from parseIntact for output that is not Intact's", () => {
    expect(parseIntact(JSON.stringify({ "windows.pslist.PsList": psTreeRows() }), {})).toBeNull();
    expect(parseIntact("not json at all", {})).toBeNull();
  });
});
