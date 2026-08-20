import { describe, it, expect } from "vitest";
import {
  reassembleScriptBlock,
  consolidateVeloScriptBlocks,
  consolidateHayabusaScriptBlocks,
  SCRIPT_BLOCK_TEXT_CAP,
} from "../../src/analysis/scriptBlockFragments.js";
import { normalizeRow } from "../../src/analysis/veloRowNormalize.js";

// The importer consolidates AFTER veloRowNormalize has un-flattened the Elasticsearch dotted keys
// back to the native nested shape, so the fixtures below take the same path.
function consolidate(rows: Record<string, unknown>[]): Record<string, unknown>[] {
  return consolidateVeloScriptBlocks(rows.map(normalizeRow));
}

const SBID = "9c440b78-a34f-40b3-99d6-dca98173b1ce";

// Windows splits a 4104 script block on a BYTE budget, so a cut can land mid-line or even
// mid-token. The three chunks below rejoin to a syntactically whole script only if they are
// concatenated with no separator at all.
const CHUNKS = ["function Invoke-Mimi { $x = 'AAA", "BBB'; Write-Output $x }", "\nInvoke-Mimi -DumpCreds"];
const FULL = CHUNKS.join("");

// ── A DetectRaptor.Windows.Detection.Evtx row as Elasticsearch reshapes it: dotted keys, a
// rendered `Message` carrying the "(N of M)" header, and the verdict in `Detection.Name`.
function drRow(part: number, chunk: string, o: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    _index: "artifact_detectraptor_windows_detection_evtx",
    "@timestamp": `2026-05-07T16:31:0${part}.000Z`,
    "Detection.Name": "PowerShell - Mimikatz",
    Computer: "WS-01",
    "System.EventID.Value": 4104,
    "System.Channel": "Microsoft-Windows-PowerShell/Operational",
    "EventData.MessageNumber": part,
    "EventData.MessageTotal": CHUNKS.length,
    "EventData.ScriptBlockId": SBID,
    "EventData.ScriptBlockText": chunk,
    Message: `Creating Scriptblock text (${part} of ${CHUNKS.length}):\n${chunk}\n\nScriptBlock ID: ${SBID}\nPath: C:\\loot.ps1`,
    "Artifact.keyword": "DetectRaptor.Windows.Detection.Evtx",
    ...o,
  };
}

// ── A Windows.Hayabusa.Rules row: verdict columns plus a " ¦ "-separated Details string.
function hbItem(
  part: number,
  chunk: string,
  o: Record<string, unknown> = {},
): { rec: Record<string, unknown>; details: Record<string, unknown> } {
  return {
    rec: {
      Timestamp: `2026-05-07T16:31:0${part}.000000000Z`,
      Computer: "WS-01",
      Channel: "Microsoft-Windows-PowerShell/Operational",
      EID: 4104,
      Level: "high",
      Title: "Malicious PowerShell Keywords",
      ...o,
    },
    details: {
      ScriptBlock: chunk,
      ScriptBlockID: SBID,
      MessageNumber: String(part),
      MessageTotal: String(CHUNKS.length),
    },
  };
}

describe("reassembleScriptBlock", () => {
  it("concatenates fragments in MessageNumber order with NO separator", () => {
    const shuffled = [
      { id: SBID, number: 3, total: 3, text: CHUNKS[2] },
      { id: SBID, number: 1, total: 3, text: CHUNKS[0] },
      { id: SBID, number: 2, total: 3, text: CHUNKS[1] },
    ];
    expect(reassembleScriptBlock(shuffled).text).toBe(FULL);
  });

  it("reports a complete block as complete, and a gapped one as partial", () => {
    const all = CHUNKS.map((text, i) => ({ id: SBID, number: i + 1, total: 3, text }));
    expect(reassembleScriptBlock(all)).toMatchObject({ parts: 3, total: 3, complete: true });

    // Only parts 1 and 3 matched the rule — part 2 never reached the importer.
    const gapped = [all[0], all[2]];
    const r = reassembleScriptBlock(gapped);
    expect(r).toMatchObject({ parts: 2, total: 3, complete: false });
    expect(r.text).toBe(CHUNKS[0] + CHUNKS[2]);
  });

  // One 4104 event that matches several rules appears once PER RULE in the export, so the same
  // MessageNumber arrives more than once. Concatenating every copy would splice a duplicated slice
  // into the middle of the script and hand the analyst evidence that never ran.
  it("counts a repeated MessageNumber once instead of splicing the slice in twice", () => {
    const dup = [
      { id: SBID, number: 1, total: 2, text: CHUNKS[0] },
      { id: SBID, number: 1, total: 2, text: CHUNKS[0] }, // same fragment, second rule
      { id: SBID, number: 2, total: 2, text: CHUNKS[1] },
    ];
    const r = reassembleScriptBlock(dup);
    expect(r.text).toBe(CHUNKS[0] + CHUNKS[1]);
    expect(r).toMatchObject({ parts: 2, total: 2, complete: true });
  });

  it("keeps the longest copy when two rules render the same fragment differently", () => {
    const r = reassembleScriptBlock([
      { id: SBID, number: 1, total: 2, text: "trunc" },
      { id: SBID, number: 1, total: 2, text: "truncated-not" },
      { id: SBID, number: 2, total: 2, text: "-tail" },
    ]);
    expect(r.text).toBe("truncated-not-tail");
  });

  // The cap must bound what is ALLOCATED, not just what is returned: joining first and slicing
  // afterwards would materialise the whole uncapped block (hundreds of MB for an adversarial input)
  // before throwing most of it away.
  it("stops concatenating at the cap instead of joining everything first", () => {
    const many = Array.from({ length: 50 }, (_, i) => ({
      id: SBID,
      number: i + 1,
      total: 50,
      text: "X".repeat(1000), // 50 KB of source for a 4 KB cap
    }));
    const r = reassembleScriptBlock(many);
    expect(r.text.length).toBe(SCRIPT_BLOCK_TEXT_CAP + 1); // capped text plus the "…" marker
    expect(r.text.endsWith("…")).toBe(true);
    expect(r.parts).toBe(50); // completeness still describes the BLOCK, not what fitted
    expect(r.complete).toBe(true);
  });

  it("adds no truncation marker when the fragments fit the cap exactly", () => {
    const exact = [
      { id: SBID, number: 1, total: 2, text: "Y".repeat(SCRIPT_BLOCK_TEXT_CAP - 1) },
      { id: SBID, number: 2, total: 2, text: "Z" },
    ];
    const r = reassembleScriptBlock(exact);
    expect(r.text.length).toBe(SCRIPT_BLOCK_TEXT_CAP);
    expect(r.text.endsWith("…")).toBe(false);
  });

  it("caps a pathologically large block so case state stays bounded", () => {
    const big = [{ id: SBID, number: 1, total: 2, text: "A".repeat(SCRIPT_BLOCK_TEXT_CAP + 500) }];
    const { text } = reassembleScriptBlock(big);
    expect(text.length).toBeLessThanOrEqual(SCRIPT_BLOCK_TEXT_CAP + 1);
    expect(text.endsWith("…")).toBe(true);
  });
});

describe("consolidateVeloScriptBlocks", () => {
  it("gives every fragment row of one block the SAME full script text", () => {
    const rows = consolidate(CHUNKS.map((c, i) => drRow(i + 1, c)));
    expect(rows).toHaveLength(3); // rows in = rows out; nothing is dropped
    for (const r of rows) {
      const ed = r.EventData as Record<string, unknown>;
      expect(ed.ScriptBlockText).toContain(FULL);
      expect(String(r.Message)).toContain(FULL);
    }
  });

  it("notes the part count so the analyst knows the text was reassembled", () => {
    const rows = consolidate(CHUNKS.map((c, i) => drRow(i + 1, c)));
    const ed = rows[0].EventData as Record<string, unknown>;
    expect(String(ed.ScriptBlockText)).toContain("reassembled from 3 script-block parts");
  });

  // Left alone, the rendered header would read "(1 of 3):" above the whole script — telling the
  // analyst the text was truncated, the exact opposite of what happened.
  it("corrects the rendered '(N of M)' header instead of leaving it claiming one part", () => {
    const [row] = consolidate(CHUNKS.map((c, i) => drRow(i + 1, c)));
    expect(String(row.Message)).toContain("(3 parts, reassembled)");
    expect(String(row.Message)).not.toContain("(1 of 3)");
    expect(String(row.Message)).toContain("ScriptBlock ID:"); // the trailer survives
  });

  it("says how many parts are MISSING when only some fragments matched the rule", () => {
    const rows = consolidate([drRow(1, CHUNKS[0]), drRow(3, CHUNKS[2])]);
    const ed = rows[0].EventData as Record<string, unknown>;
    expect(String(ed.ScriptBlockText)).toContain("reassembled from 2 of 3 script-block parts");
  });

  it("leaves a single-part block, a block with no ScriptBlockId, and a non-4104 row untouched", () => {
    const single = drRow(1, "whoami", { "EventData.MessageTotal": 1 });
    const noId = drRow(1, "whoami", { "EventData.ScriptBlockId": undefined });
    const other = drRow(1, "whoami", { "System.EventID.Value": 4688 });
    for (const raw of [single, noId, other]) {
      const [out] = consolidate([raw]);
      const ed = (out.EventData ?? {}) as Record<string, unknown>;
      expect(String(ed.ScriptBlockText ?? "")).not.toContain("reassembled");
    }
  });

  // The end-to-end shape of the duplicate case: fragment 1 matched two rules, fragment 2 one.
  it("does not duplicate a slice when one fragment matched more than one rule", () => {
    const rows = consolidate([
      drRow(1, CHUNKS[0]),
      drRow(1, CHUNKS[0], { "Detection.Name": "PowerShell - AMSI Bypass" }),
      drRow(2, CHUNKS[1]),
    ]);
    const text = String((rows[0].EventData as Record<string, unknown>).ScriptBlockText);
    expect(text.split(CHUNKS[0]).length - 1).toBe(1); // the slice appears exactly once
    expect(text).toContain(CHUNKS[0] + CHUNKS[1]);
  });

  // A THIRD row shape, seen on a real Windows.Hayabusa.Rules collection (case INC-2026-016): the raw
  // event rides under `_Event`, not `EventData` or `Event.EventData`. The row still reaches THIS
  // importer rather than the Hayabusa one, because it carries `_Source` and the Velociraptor
  // detector claims any `_Source`. rowMessage() already reads `_Event`; the fragment reader did not,
  // so a split block in this shape stayed one alert per fragment.
  function underscoreEventRow(part: number, chunk: string): Record<string, unknown> {
    return {
      Timestamp: `2025-03-14T21:14:4${part}.000000000Z`,
      Computer: "WIN11.windomain.local",
      Channel: "Microsoft-Windows-PowerShell/Operational",
      EID: 4104,
      Level: "medium",
      Title: "Potentially Malicious PwSh",
      RecordID: 1400 + part,
      Details: `ScriptBlock: ${chunk}`,
      _Source: "Windows.Hayabusa.Rules",
      _Event: {
        System: {
          EventID: { Value: 4104 },
          Computer: "WIN11.windomain.local",
          Channel: "Microsoft-Windows-PowerShell/Operational",
        },
        EventData: {
          MessageNumber: String(part),
          MessageTotal: "2",
          ScriptBlockText: chunk,
          ScriptBlockId: SBID,
          Path: "C:\\TrigonaSim\\tools\\uac-bypass.ps1",
        },
      },
    };
  }

  it("reads a block whose raw event sits under `_Event` (Windows.Hayabusa.Rules shape)", () => {
    const rows = consolidate([underscoreEventRow(1, CHUNKS[0]), underscoreEventRow(2, CHUNKS[1])]);
    for (const row of rows) {
      const ed = (row._Event as Record<string, unknown>).EventData as Record<string, unknown>;
      expect(String(ed.ScriptBlockText)).toContain(CHUNKS[0] + CHUNKS[1]);
    }
  });

  it("leaves a single-part `_Event` block alone (the real INC-2026-016 rows are all 1 of 1)", () => {
    const one = underscoreEventRow(1, "whoami");
    ((one._Event as Record<string, unknown>).EventData as Record<string, unknown>).MessageTotal = "1";
    const [out] = consolidate([one]);
    const ed = (out._Event as Record<string, unknown>).EventData as Record<string, unknown>;
    expect(String(ed.ScriptBlockText)).toBe("whoami");
  });

  // A `_Event` row's verdict lives in a top-level `Title` that classify() does not treat as a
  // verdict, so mapGeneric puts it in neither the description nor the aggregation key. Before
  // consolidation the differing fragment text kept two rules apart by accident. Handing both rows
  // identical text removed that accident and one rule's verdict disappeared from the case entirely.
  // Reassembly is therefore scoped PER RULE: each alert joins the parts its own rule matched.
  it("keeps two rules over one `_Event` block apart instead of dropping a verdict", () => {
    const a = underscoreEventRow(1, CHUNKS[0]);
    const b = underscoreEventRow(2, CHUNKS[1]);
    b.Title = "UAC Bypass Attempt";
    const rows = consolidate([a, b]);
    const text = (r: Record<string, unknown>): string =>
      String(((r._Event as Record<string, unknown>).EventData as Record<string, unknown>).ScriptBlockText);
    // Neither row is given the other rule's slice, so neither verdict can collapse into the other.
    expect(text(rows[0])).not.toContain(CHUNKS[1]);
    expect(text(rows[1])).not.toContain(CHUNKS[0]);
  });

  it("still joins every fragment when ONE rule matched them all", () => {
    const rows = consolidate([underscoreEventRow(1, CHUNKS[0]), underscoreEventRow(2, CHUNKS[1])]);
    const ed = (rows[0]._Event as Record<string, unknown>).EventData as Record<string, unknown>;
    expect(String(ed.ScriptBlockText)).toContain(CHUNKS[0] + CHUNKS[1]);
  });

  // rowMessage() falls back to `_Event.Message`, so a stale nested message both blocks consolidation
  // and leaves the analyst reading one slice above the full reassembled text.
  it("rewrites `_Event.Message` too, not just the nested event data", () => {
    const mk = (part: number, chunk: string): Record<string, unknown> => {
      const r = underscoreEventRow(part, chunk);
      delete r.Details;
      (r._Event as Record<string, unknown>).Message = `Creating Scriptblock text (${part} of 2):\n${chunk}`;
      return r;
    };
    const rows = consolidate([mk(1, CHUNKS[0]), mk(2, CHUNKS[1])]);
    for (const r of rows) {
      const msg = String((r._Event as Record<string, unknown>).Message);
      expect(msg).toContain(CHUNKS[0] + CHUNKS[1]);
    }
  });

  it("never joins the same ScriptBlockId across two hosts", () => {
    const rows = consolidate([drRow(1, CHUNKS[0]), drRow(2, CHUNKS[1], { Computer: "WS-02" })]);
    const text = (i: number): string =>
      String((rows[i].EventData as Record<string, unknown>).ScriptBlockText);
    expect(text(0)).not.toContain(CHUNKS[1]);
    expect(text(1)).not.toContain(CHUNKS[0]);
  });
});

describe("consolidateHayabusaScriptBlocks", () => {
  it("gives every fragment's Details the SAME full script text", () => {
    const items = consolidateHayabusaScriptBlocks(CHUNKS.map((c, i) => hbItem(i + 1, c)));
    expect(items).toHaveLength(3);
    for (const it of items) expect(String(it.details.ScriptBlock)).toContain(FULL);
  });

  it("leaves a single-part block untouched", () => {
    const one = hbItem(1, "whoami");
    one.details.MessageTotal = "1";
    const [out] = consolidateHayabusaScriptBlocks([one]);
    expect(String(out.details.ScriptBlock)).toBe("whoami");
  });
});
