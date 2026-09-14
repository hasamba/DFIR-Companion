// #933 item 12, second half (#1016): a run envelope written by the invoking script — the command,
// the exit status, stderr as its own field, the digests — travelling WITH the stdout it describes,
// is what makes an empty Volatility export "completed with no rows" or "did not complete". Every
// verdict is the envelope's statement (uploader-supplied, unsigned), read from the exit status and
// the whole stderr, and never speaks for pages the dump does not hold.
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parseMemory } from "../../src/analysis/memoryImport.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";
import {
  isRunEnvelopeUpload,
  RUN_ENVELOPE_TYPE,
  RUNS_PER_BUNDLE_MAX,
  STDERR_MAX,
} from "../../src/analysis/memoryRunEnvelope.js";
import { canonicalEventEnvelopeSchema } from "../../src/analysis/canonicalEvent.js";

const sha = (s: string | Buffer) => `sha256:${createHash("sha256").update(s).digest("hex")}`;
const IMAGE = sha("image-bytes");
const MALFIND_HEADER =
  "PID\tProcess\tStart VPN\tEnd VPN\tTag\tProtection\tCommitCharge\tPrivateMemory\tFile output\tNotes\tHexdump\tDisasm";
const EMPTY_TEXT = `Volatility 3 Framework 2.7.0\n${MALFIND_HEADER}\n`;
const MALFIND_ROWS = JSON.stringify([
  {
    __children: [],
    PID: 1234,
    Process: "svchost.exe",
    "Start VPN": "0x1a0000",
    "End VPN": "0x1a1fff",
    Tag: "VadS",
    Protection: "PAGE_EXECUTE_READWRITE",
    CommitCharge: 2,
    PrivateMemory: 1,
    "File output": "Disabled",
    Notes: "MZ header",
    Hexdump: "4d 5a",
    Disasm: "",
  },
  {
    __children: [],
    PID: 5678,
    Process: "explorer.exe",
    "Start VPN": "0x2b0000",
    "End VPN": "0x2b1fff",
    Tag: "VadS",
    Protection: "PAGE_EXECUTE_READWRITE",
    CommitCharge: 1,
    PrivateMemory: 1,
    "File output": "Disabled",
    Notes: "",
    Hexdump: "",
    Disasm: "",
  },
]);
const CRASH_BITMAP = JSON.stringify([
  {
    __children: [],
    Signature: "PAGE",
    MajorVersion: 15,
    MinorVersion: 7601,
    DirectoryTableBase: "0x187000",
    PfnDataBase: "0x1",
    PsLoadedModuleList: "0x2",
    PsActiveProcessHead: "0x3",
    MachineImageType: "0x8664",
    NumberProcessors: 1,
    KdDebuggerDataBlock: "0x4",
    DumpType: "Bitmap Dump (0x5)",
    SystemUpTime: "0:12:34",
    SystemTime: "2012-07-22T02:45:08+00:00",
    Comment: "",
  },
]);
const run = (over: Record<string, unknown> = {}) => ({
  type: RUN_ENVELOPE_TYPE,
  envelopeVersion: 1,
  command: "vol -r json -f image.raw windows.malfind",
  plugin: "windows.malfind",
  renderer: "json",
  volatilityVersion: "2.7.0",
  symbols: "windows/ntkrnlmp.pdb/…",
  exitStatus: 0,
  stdout: "[]\n",
  stderr: "",
  imageSha256: IMAGE,
  startedAt: "2026-05-02T10:00:00Z",
  endedAt: "2026-05-02T10:00:09Z",
  ...over,
});
const bundle = (runs: unknown[]) => JSON.stringify({ type: RUN_ENVELOPE_TYPE, envelopeVersion: 1, runs });
const runRows = (text: string, opts: Record<string, unknown> = {}) =>
  parseMemory(text, opts).events.filter((e) => e.description.startsWith("Memory run envelope"));

describe("what one envelope establishes", () => {
  it("exit 0, a header, zero rows, no page error: completed with no rows over the pages the image holds — Low, worded as the envelope's statement", () => {
    const r = parseMemory(JSON.stringify(run({ stdout: EMPTY_TEXT })));
    expect(r.format).toBe("volatility-run-envelope");
    const rows = r.events.filter((e) => e.description.startsWith("Memory run envelope"));
    expect(rows).toHaveLength(1);
    const e = rows[0];
    expect(e.severity).toBe("Low");
    expect(e.timestamp).toMatch(/^2026-05-02T10:00:00/);
    expect(e.description).toContain(
      "Memory run envelope (uploader-supplied, unsigned) states: windows.malfind — windows.malfind completed with no rows over the pages this image holds and the structures the plugin reads; not evidence about pages the dump does not hold",
    );
    expect(e.description).toContain("[exit 0; 0 rows in the embedded export; Volatility 2.7.0;");
    expect(e.description).toContain("(digest over the embedded text, UTF-8)");
    expect(e.description).toContain(
      "stderr: no diagnostic line; command: vol -r json -f image.raw windows.malfind]",
    );
    expect(e.description).not.toMatch(/clean|no malware|nothing found/);
    // The export's own shape row imports beside it, unchanged.
    expect(r.events.some((x) => x.description.startsWith("Memory export holds zero rows"))).toBe(true);
    expect(canonicalEventEnvelopeSchema.safeParse(e.canonical).success).toBe(true);
    expect(e.canonical?.memoryRun).toMatchObject({
      plugin: "windows.malfind",
      exitStatus: 0,
      stdoutEncoding: "text-utf8",
      stdoutSha256: sha(Buffer.from(EMPTY_TEXT, "utf8")),
      imageSha256: IMAGE,
      bound: true,
      verdict: { kind: "completed-no-rows", rows: 0 },
    });
  });

  it("a validation failure on stderr, or a non-zero exit: did not complete; the absence of rows is not evidence — Medium", () => {
    const req = runRows(
      JSON.stringify(
        run({
          exitStatus: 1,
          stderr:
            "Volatility 3 Framework 2.7.0\nUnsatisfied requirement plugins.Malfind.kernel.symbol_table_name: \nUnable to validate the plugin requirements: ['plugins.Malfind.kernel.symbol_table_name']\n",
        }),
      ),
    )[0];
    expect(req.severity).toBe("Medium");
    expect(req.description).toContain(
      "did not complete: symbol/translation validation failed: Unsatisfied requirement plugins.Malfind.kernel.symbol_table_name:; the absence of rows is not evidence",
    );
    expect(req.canonical?.memoryRun?.verdict.kind).toBe("did-not-complete-validation");
    const exit = runRows(JSON.stringify(run({ exitStatus: 137 })))[0];
    expect(exit.description).toContain(
      "did not complete: exit status 137; the absence of rows is not evidence",
    );
    expect(exit.severity).toBe("Medium");
  });

  it("a page error on stderr after rows: did not complete after N rows; later candidates may never have been searched", () => {
    const rows = runRows(
      JSON.stringify(
        run({
          stdout: MALFIND_ROWS,
          stderr:
            "Volatility was unable to read a requested page:\nPage error 0x7ff8 in layer layer_name (Page Fault at entry 0x0 in table page directory)\n",
        }),
      ),
    );
    expect(rows[0].description).toContain(
      "did not complete after 2 rows; later candidates may never have been searched",
    );
    expect(rows[0].canonical?.memoryRun?.verdict).toMatchObject({
      kind: "did-not-complete-page-error",
      rows: 2,
    });
    expect(rows[0].severity).toBe("Medium");
  });

  it("exit 0 wins over a verbose optional-import traceback on stderr; the traceback is shown as unverified", () => {
    const rows = runRows(
      JSON.stringify(
        run({
          stdout: EMPTY_TEXT,
          stderr:
            "Traceback (most recent call last):\n  File \"x.py\", line 1\nModuleNotFoundError: No module named 'yara'\n",
        }),
      ),
    );
    expect(rows[0].description).toContain("completed with no rows");
    expect(rows[0].description).toContain("stderr carries a traceback (unverified; the run exited 0)");
    expect(rows[0].severity).toBe("Low");
    expect(rows[0].canonical?.memoryRun?.verdict.tracebackOnSuccess).toBe(true);
  });

  it("a Volatility 2 command line names the legacy workflow; the export is not read", () => {
    const rows = runRows(
      JSON.stringify(
        run({ command: "vol.py --profile=Win7SP1x64 -f image.raw malfind", stdout: EMPTY_TEXT }),
      ),
    );
    expect(rows[0].description).toContain(
      "a Volatility 2 run (profile-based); the export is not read; the envelope names the run: vol.py --profile=Win7SP1x64 -f image.raw malfind",
    );
    expect(rows[0].canonical?.memoryRun?.verdict.kind).toBe("volatility-2");
  });

  it("a bitmap dump from a crashinfo run of the SAME image qualifies an empty user-space result; another image, or no crashinfo, does not", () => {
    const same = runRows(
      bundle([
        run({
          plugin: "windows.crashinfo",
          command: "vol -r json -f image.raw windows.crashinfo",
          stdout: CRASH_BITMAP,
        }),
        run({ stdout: EMPTY_TEXT }),
      ]),
    );
    const malfind = same.find((e) => e.canonical?.memoryRun?.plugin === "windows.malfind")!;
    expect(malfind.description).toContain(
      "over a dump that may not hold user-space pages; an empty result does not clear user-space behaviour",
    );
    const other = runRows(
      bundle([
        run({ plugin: "windows.crashinfo", stdout: CRASH_BITMAP, imageSha256: sha("another-image") }),
        run({ stdout: EMPTY_TEXT }),
      ]),
    ).find((e) => e.canonical?.memoryRun?.plugin === "windows.malfind")!;
    expect(other.description).not.toContain("user-space");
    expect(other.description).toContain("dump type not established for this run");
    const pslist = runRows(
      bundle([
        run({ plugin: "windows.crashinfo", stdout: CRASH_BITMAP }),
        run({ plugin: "windows.pslist", stdout: EMPTY_TEXT }),
      ]),
    ).find((e) => e.canonical?.memoryRun?.plugin === "windows.pslist")!;
    expect(pslist.description).not.toContain("user-space");
  });
});

describe("binding, provenance, bounds", () => {
  it("a stated stdoutSha256 that disagrees with the embedded text unbinds the run; the export still imports", () => {
    const r = parseMemory(JSON.stringify(run({ stdout: EMPTY_TEXT, stdoutSha256: sha("something else") })));
    const row = r.events.find((e) => e.description.startsWith("Memory run envelope"))!;
    expect(row.description).toContain("differs from the stated stdoutSha256");
    expect(row.description).not.toContain("completed");
    expect(row.canonical?.memoryRun?.bound).toBe(false);
    expect(r.events.some((x) => x.description.startsWith("Memory export holds zero rows"))).toBe(false);
    // Bytes, when the collector supplies them: the digest is over the bytes.
    const bytes = Buffer.from(EMPTY_TEXT, "utf8");
    const ok = runRows(
      JSON.stringify(
        run({ stdout: undefined, stdoutBase64: bytes.toString("base64"), stdoutSha256: sha(bytes) }),
      ),
    )[0];
    expect(ok.canonical?.memoryRun).toMatchObject({
      bound: true,
      stdoutEncoding: "bytes",
      statedStdoutSha256: sha(bytes),
    });
    expect(ok.description).toContain("completed with no rows");
    // A stated digest that agrees with the UTF-8 text binds too.
    expect(
      runRows(JSON.stringify(run({ stdout: EMPTY_TEXT, stdoutSha256: sha(bytes) })))[0].canonical?.memoryRun
        ?.bound,
    ).toBe(true);
  });

  it("no export embedded: applied to nothing, said; a non-digest imageSha256 unbinds", () => {
    const none = runRows(JSON.stringify(run({ stdout: undefined })))[0];
    expect(none.description).toContain(
      "no export embedded; applied to nothing — embed the run's stdout in the envelope",
    );
    expect(none.canonical?.memoryRun?.verdict.kind).toBe("unbound");
    const badImage = runRows(JSON.stringify(run({ stdout: EMPTY_TEXT, imageSha256: "not-a-digest" })))[0];
    expect(badImage.description).toContain("imageSha256 is not a sha256 digest");
    expect(badImage.canonical?.memoryRun?.bound).toBe(false);
  });

  it("stderr is scanned whole: a page error after a long prefix is seen; past the bound the verdict is indeterminate, never completed", () => {
    const long = `${"warning line\n".repeat(20_000)}Volatility was unable to read a requested page: 0x1\n`;
    expect(long.length).toBeLessThan(STDERR_MAX);
    expect(runRows(JSON.stringify(run({ stdout: EMPTY_TEXT, stderr: long })))[0].description).toContain(
      "did not complete after 0 rows",
    );
    const over = `${"x".repeat(STDERR_MAX + 1)}\n`;
    const row = runRows(JSON.stringify(run({ stdout: EMPTY_TEXT, stderr: over })))[0];
    expect(row.description).toContain("indeterminate: stderr exceeds the bound the importer reads");
    expect(row.description).not.toContain("completed");
    expect(row.severity).toBe("Medium");
  });

  it("hostile stderr and command text are neutralised; the identity is the whole envelope; a re-import folds", () => {
    const evil = runRows(
      JSON.stringify(
        run({
          stdout: EMPTY_TEXT,
          exitStatus: 1,
          stderr: "Unsatisfied requirement ] [fake: injected\n",
          command: "vol ] [x",
        }),
      ),
    )[0];
    expect(evil.description).not.toContain("] [fake");
    expect(evil.description).not.toContain("] [x");
    const a = runRows(JSON.stringify(run({ stdout: EMPTY_TEXT })))[0];
    const b = runRows(
      JSON.stringify(
        run({ stdout: EMPTY_TEXT, stderr: "Volatility was unable to read a requested page: 0x1\n" }),
      ),
    )[0];
    expect(a.aggKey).not.toBe(b.aggKey);
    expect(runRows(JSON.stringify(run({ stdout: EMPTY_TEXT })))[0].aggKey).toBe(a.aggKey);
    const twice = parseMemory(bundle([run({ stdout: EMPTY_TEXT }), run({ stdout: EMPTY_TEXT })]), {
      aggregate: true,
    });
    expect(twice.events.filter((e) => e.description.startsWith("Memory run envelope"))).toHaveLength(1);
  });

  it("a bundle reads 256 runs and counts the rest; the exports' rows and counts merge; detection keys on the discriminator", () => {
    const many = bundle(
      Array.from({ length: RUNS_PER_BUNDLE_MAX + 2 }, (_, i) =>
        run({
          stdout: EMPTY_TEXT,
          startedAt: `2026-05-02T10:${String(i % 60).padStart(2, "0")}:${String(Math.floor(i / 60)).padStart(2, "0")}Z`,
        }),
      ),
    );
    const r = parseMemory(many);
    expect(r.note).toContain(`2 further run(s) beyond the ${RUNS_PER_BUNDLE_MAX} read`);
    const withRows = parseMemory(
      bundle([run({ stdout: MALFIND_ROWS }), run({ plugin: "windows.crashinfo", stdout: CRASH_BITMAP })]),
    );
    expect(withRows.total).toBe(5); // three export rows and two run records
    expect(withRows.injected).toBe(2);
    expect(withRows.events.some((e) => e.description.includes("svchost.exe"))).toBe(true);
    expect(detectImportKind("x.run.json", JSON.stringify(run()))).toBe("memory");
    expect(detectImportKind("runs.json", bundle([run()]))).toBe("memory");
    expect(
      isRunEnvelopeUpload({ command: "npm test", plugin: "jest", exitStatus: 0, stdout: "[]", stderr: "" }),
    ).toBe(false);
    expect(isRunEnvelopeUpload({ runs: [{ plugin: "x", exitStatus: 0 }] })).toBe(false);
    expect(
      parseMemory(JSON.stringify({ command: "npm test", plugin: "jest", exitStatus: 0, stdout: "[]" }))
        .format,
    ).not.toBe("volatility-run-envelope");
  });
});

// Code round 1 (Codex): the cases the review named.
describe("code round 1", () => {
  it("one bundle-wide budget: two runs with rows under maxEvents:1 emit one row; total counts export rows and run records", () => {
    const r = parseMemory(bundle([run({ stdout: MALFIND_ROWS }), run({ stdout: MALFIND_ROWS })]), {
      maxEvents: 1,
      aggregate: false,
    });
    expect(r.events).toHaveLength(1);
    expect(r.kept).toBe(1);
    expect(r.total).toBe(6);
    expect(r.dropped).toBe(5);
  });

  it("an export labelled with another plugin unbinds the envelope; the export still imports", () => {
    const r = parseMemory(JSON.stringify(run({ stdout: JSON.stringify({ "windows.pslist.PsList": [] }) })));
    const row = r.events.find((e) => e.description.startsWith("Memory run envelope"))!;
    expect(row.description).toContain(
      "the envelope names windows.malfind; the export is labelled windows.pslist.PsList — applied to nothing",
    );
    expect(row.canonical?.memoryRun?.bound).toBe(false);
    expect(row.description).not.toContain("completed");
    expect(r.events.some((e) => e.description.startsWith("Memory export holds zero rows"))).toBe(true);
    // The same plugin under Volatility's full class name binds.
    const same = runRows(
      JSON.stringify(run({ stdout: JSON.stringify({ "windows.malfind.Malfind": [] }) })),
    )[0];
    expect(same.canonical?.memoryRun?.bound).toBe(true);
  });

  it("a nested envelope or a bare `{}` is not a readable export: indeterminate, never completed, and never read recursively", () => {
    const nested = runRows(JSON.stringify(run({ stdout: JSON.stringify(run({ stdout: EMPTY_TEXT })) })));
    expect(nested).toHaveLength(1);
    expect(nested[0].description).toContain(
      "indeterminate: the embedded stdout is not a readable Volatility export",
    );
    const bare = runRows(JSON.stringify(run({ stdout: "{}" })))[0];
    expect(bare.description).toContain("indeterminate");
    expect(bare.description).not.toContain("completed");
  });

  it("oversized metadata is refused at the schema; base64 is bounded before decoding", () => {
    const r = parseMemory(JSON.stringify(run({ stdout: EMPTY_TEXT, command: "x".repeat(5000) })));
    expect(r.events.filter((e) => e.description.startsWith("Memory run envelope"))).toHaveLength(0);
    expect(r.note).toContain("not a run envelope");
  });

  it("an unsupported envelopeVersion reads nothing; a single run object is a bundle of one", () => {
    const r = parseMemory(
      JSON.stringify({ type: RUN_ENVELOPE_TYPE, envelopeVersion: 999, runs: [run({ stdout: EMPTY_TEXT })] }),
    );
    expect(r.events).toHaveLength(0);
    expect(r.note).toContain("envelopeVersion is not 1");
    expect(runRows(JSON.stringify(run({ stdout: EMPTY_TEXT, envelopeVersion: 999 })))).toHaveLength(0);
    expect(runRows(JSON.stringify(run({ stdout: EMPTY_TEXT })))).toHaveLength(1);
  });

  it("marker precedence: a page error with a non-zero exit keeps 'after N rows'; a prefixed marker is seen", () => {
    const both = runRows(
      JSON.stringify(
        run({
          stdout: MALFIND_ROWS,
          exitStatus: 1,
          stderr: "Volatility was unable to read a requested page: 0x1\n",
        }),
      ),
    )[0];
    expect(both.description).toContain(
      "did not complete after 2 rows; later candidates may never have been searched",
    );
    expect(both.description).toContain("exit status 1");
    const prefixed = runRows(
      JSON.stringify(
        run({
          stdout: EMPTY_TEXT,
          stderr:
            "\u001b[31mERROR\u001b[0m volatility3: Volatility was unable to read a requested page: 0x1\n",
        }),
      ),
    )[0];
    expect(prefixed.description).toContain("did not complete after 0 rows");
    const validationFirst = runRows(
      JSON.stringify(
        run({
          stdout: EMPTY_TEXT,
          exitStatus: 1,
          stderr:
            "Volatility was unable to read a requested page: 0x1\nUnsatisfied requirement plugins.Malfind.kernel: \n",
        }),
      ),
    )[0];
    expect(validationFirst.description).toContain("symbol/translation validation failed");
  });

  it("embedded bytes: a UTF-8 BOM and a UTF-16LE BOM are read; invalid UTF-8 is not guessed at; CRLF text reads", () => {
    const bom8 = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(EMPTY_TEXT, "utf8")]);
    const a = runRows(JSON.stringify(run({ stdout: undefined, stdoutBase64: bom8.toString("base64") })))[0];
    expect(a.canonical?.memoryRun).toMatchObject({
      bound: true,
      stdoutCharset: "utf-8 (BOM)",
      verdict: { kind: "completed-no-rows" },
    });
    const u16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(EMPTY_TEXT, "utf16le")]);
    const b = runRows(JSON.stringify(run({ stdout: undefined, stdoutBase64: u16.toString("base64") })))[0];
    expect(b.canonical?.memoryRun).toMatchObject({
      bound: true,
      stdoutCharset: "utf-16le (BOM)",
      verdict: { kind: "completed-no-rows" },
    });
    const bad = runRows(
      JSON.stringify(
        run({ stdout: undefined, stdoutBase64: Buffer.from([0x5b, 0xe9, 0x5d]).toString("base64") }),
      ),
    )[0];
    expect(bad.description).toContain("not UTF-8 and carry no UTF-16 BOM; the charset is not established");
    expect(bad.canonical?.memoryRun?.bound).toBe(false);
    const crlf = runRows(JSON.stringify(run({ stdout: EMPTY_TEXT.replace(/\n/g, "\r\n") })))[0];
    expect(crlf.description).toContain("completed with no rows");
  });

  it("the crashinfo qualification needs the exact windows.crashinfo plugin", () => {
    const rows = runRows(
      bundle([
        run({
          plugin: "attacker.crashinfo",
          command: "vol -r json -f image.raw attacker.crashinfo",
          stdout: CRASH_BITMAP,
        }),
        run({ stdout: EMPTY_TEXT }),
      ]),
    );
    const malfind = rows.find((e) => e.canonical?.memoryRun?.plugin === "windows.malfind")!;
    expect(malfind.description).not.toContain("user-space");
    const full = runRows(
      bundle([
        run({
          plugin: "windows.crashinfo.Crashinfo",
          command: "vol -r json -f image.raw windows.crashinfo",
          stdout: CRASH_BITMAP,
        }),
        run({ stdout: EMPTY_TEXT }),
      ]),
    ).find((e) => e.canonical?.memoryRun?.plugin === "windows.malfind")!;
    expect(full.description).toContain("user-space");
  });
});
