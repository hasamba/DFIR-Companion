import { describe, it, expect } from "vitest";
import {
  confirmCandidates,
  confirmListCsv,
  confirmListMarkdown,
  parseClientCsv,
} from "../../src/analysis/huntConfirmList.js";
import { recordObservations, EMPTY_INVENTORY } from "../../src/analysis/huntInventory.js";
import { huntFieldsOf } from "../../src/analysis/huntArtifactFields.js";
import { EMPTY_BASELINE, markInputSchema } from "../../src/analysis/clientProfile.js";
import { prefetchRow } from "../helpers/huntFakes.js";

function inventory() {
  const rows = [
    ...[0, 1, 2, 3].map((i) => prefetchRow(`c${i}`, i, "chrome.exe", "C:\\Program Files\\Google")),
    prefetchRow("r0", 0, "=cmd.exe", "C:\\Users\\x\\Downloads"),
  ];
  const obs = rows.map((e) => {
    const fields = huntFieldsOf(e)!;
    return {
      fields,
      host: { key: `s/C.${e.asset}`, basis: "client" as const, hostname: e.asset! },
      at: e.timestamp,
    };
  });
  return recordObservations(EMPTY_INVENTORY, obs, "now");
}

describe("the client's confirm list (#2670)", () => {
  it("lists every unsettled item, rarest first", () => {
    const list = confirmCandidates(inventory(), EMPTY_BASELINE, new Set(), "2026-01-01T00:00:00Z");
    expect(list.map((c) => c.program)).toEqual(["=cmd.exe", "chrome.exe"]);
    expect(list[1].hostCount).toBe(4);
  });

  it("a Not-allowed item is settled and leaves the list; an unconfirmed one stays", () => {
    const baseline = {
      ...EMPTY_BASELINE,
      marks: [
        {
          ...markInputSchema.parse({ verdict: "not-allowed", family: "program", program: "chrome.exe" }),
          id: "m",
          source: "s",
          recordedBy: "a",
          recordedAt: "t",
        },
      ],
    };
    expect(confirmCandidates(inventory(), baseline, new Set(), "t").map((c) => c.program)).toEqual([
      "=cmd.exe",
    ]);
  });

  it("guards every CSV cell against formula injection", () => {
    const csv = confirmListCsv(confirmCandidates(inventory(), EMPTY_BASELINE, new Set(), "t"));
    expect(csv).toContain(`"'=cmd.exe"`);
    expect(csv.split("\r\n")[0]).toBe(
      "family,program,path_pattern,host_count,hosts,evidence,publisher_unverified,sha256,first_seen,verdict,note",
    );
  });

  it("escapes the Markdown table", () => {
    const md = confirmListMarkdown(
      confirmCandidates(inventory(), EMPTY_BASELINE, new Set(), "t"),
      "Client|A",
    );
    expect(md).toContain("# Please confirm — Client\\|A");
  });

  it("reads the client's filled CSV back, skipping unanswered and bad rows", () => {
    const csv = [
      "family,program,path_pattern,host_count,hosts,evidence,publisher_unverified,sha256,first_seen,verdict,note",
      `"program","'=cmd.exe","\\users\\*\\downloads","1","WS-000","execution","","","t","Not allowed","torrent client"`,
      `"program","chrome.exe","\\program files\\google","4","","execution","","","t","maybe",""`,
      `"program","other.exe","","1","","execution","","","t","",""`,
    ].join("\r\n");
    const r = parseClientCsv(csv);
    expect(r.marks).toEqual([
      expect.objectContaining({
        verdict: "not-allowed",
        program: "=cmd.exe",
        pathPattern: "\\users\\*\\downloads",
        note: "torrent client",
      }),
    ]);
    expect(r.skipped).toEqual([{ line: 3, reason: 'unknown verdict "maybe"' }]);
  });

  it("refuses a CSV without the key columns", () => {
    expect(parseClientCsv("a,b\n1,2").skipped[0].reason).toMatch(/header must name/);
  });
});
