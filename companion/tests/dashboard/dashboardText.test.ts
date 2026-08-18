import { describe, expect, it } from "vitest";
import type { TextApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-text.js — parsing, normalisation and shape-fingerprinting (#415).

const t = loadDashboardModule<TextApi>("dashboard-text.js");

// The pipe-delimited editors (playbook tasks, hypotheses, custody entries) all round-trip through
// this pair. Neither is quote-aware or escape-aware, so a pipe inside a field splits it — worth
// knowing before anyone stores free text through them.
describe("parseRows / rowsToText / linesToArray", () => {
  it("splits on pipes and trims, skipping blank lines", () => {
    expect(t.parseRows("a | b\n\n c|d \n", ["x", "y"])).toEqual([
      { x: "a", y: "b" },
      { x: "c", y: "d" },
    ]);
  });

  it("fills missing columns with the empty string rather than undefined", () => {
    expect(t.parseRows("only", ["x", "y"])).toEqual([{ x: "only", y: "" }]);
  });

  it("round-trips a row through rowsToText", () => {
    const rows = [{ x: "a", y: "b" }];
    expect(t.parseRows(t.rowsToText(rows, ["x", "y"]), ["x", "y"])).toEqual(rows);
  });

  it("splits a field that itself contains a pipe", () => {
    expect(t.parseRows("a|b|c", ["x", "y"])).toEqual([{ x: "a", y: "b" }]);
  });

  it("renders an absent array as an empty string", () => {
    expect(t.rowsToText(null, ["x"])).toBe("");
  });

  it("linesToArray trims and drops blanks", () => {
    expect(t.linesToArray(" a \n\n  \nb")).toEqual(["a", "b"]);
  });
});

describe("truncate", () => {
  it("keeps a short string whole", () => {
    expect(t.truncate("abc", 5)).toBe("abc");
    expect(t.truncate("abcde", 5)).toBe("abcde");
  });

  // The ellipsis replaces the last kept character, so the result is exactly `n` characters — not
  // `n` plus an ellipsis.
  it("cuts to exactly n characters including the ellipsis", () => {
    expect(t.truncate("abcdef", 4)).toBe("abc…");
    expect(t.truncate("abcdef", 4)).toHaveLength(4);
  });

  it("coerces a non-string rather than throwing", () => {
    expect(t.truncate(12345, 3)).toBe("12…");
    expect(t.truncate(null, 10)).toBe("null");
  });
});

describe("splitEventTitle", () => {
  it("splits on the first ' - ' only", () => {
    expect(t.splitEventTitle("Boot - at 3pm - again")).toEqual({ title: "Boot", rest: "at 3pm - again" });
  });

  it("returns the whole string as the title when there is no separator", () => {
    expect(t.splitEventTitle("Boot")).toEqual({ title: "Boot", rest: "" });
    expect(t.splitEventTitle("Boot-at-3pm")).toEqual({ title: "Boot-at-3pm", rest: "" });
  });
});

// Defanged indicators arrive pasted from reports and ticket comments. Refanging is deliberately
// aggressive, including collapsing spaces around dots — which is what makes "soulversr .com" work
// and also what makes it unsuitable for anything but indicator extraction.
describe("huntRefang", () => {
  it.each([
    ["hxxps://evil[.]com", "https://evil.com"],
    ["hxxp://evil(dot)com", "http://evil.com"],
    ["evil[dot]com", "evil.com"],
    ["evil dot com", "evil.com"],
    ["10[.]0[.]0[.]1", "10.0.0.1"],
    ["http[:]//evil.com", "http://evil.com"],
    ["soulversr .com", "soulversr.com"],
  ])("%s -> %s", (input, expected) => expect(t.huntRefang(input)).toBe(expected));

  it("leaves an already-fanged indicator alone", () => {
    expect(t.huntRefang("https://evil.com/a")).toBe("https://evil.com/a");
  });

  it("returns an empty string for nothing", () => {
    expect(t.huntRefang(null)).toBe("");
  });
});

// The display split behind the Executive Summary, Attack Path and Narrative Timeline panels. The
// model writes those as one unbroken block, so without this the whole narrative is a single
// paragraph running the full width of the page.
//
// IT IS A DISPLAY TRANSFORM, so what these pin hardest is what it must NOT do: never lose a
// character, never cut inside a hostname or a version, and never restructure text the author
// already shaped by hand.
describe("proseSentences", () => {
  it("splits on a sentence end followed by a capital", () => {
    expect(t.proseSentences("One thing happened. Then another did.")).toEqual([
      "One thing happened.",
      "Then another did.",
    ]);
  });

  // The reason a naive `split(". ")` is wrong on this data: DFIR prose is full of dotted tokens.
  it("does not cut inside a hostname, a version or a filename", () => {
    expect(t.proseSentences("win11.windomain.local ran lsass.exe under v1.2 today")).toEqual([
      "win11.windomain.local ran lsass.exe under v1.2 today",
    ]);
  });

  it("keeps an abbreviation with the sentence it belongs to", () => {
    expect(t.proseSentences("Tools e.g. Mimikatz were staged.")).toEqual([
      "Tools e.g. Mimikatz were staged.",
    ]);
    expect(t.proseSentences("Reported by A. Smith today.")).toEqual(["Reported by A. Smith today."]);
  });

  it("splits before a sentence that opens with a date or a quote", () => {
    expect(t.proseSentences("It began. 2025-03-14 was the first day.")).toEqual([
      "It began.",
      "2025-03-14 was the first day.",
    ]);
    expect(t.proseSentences("It began. 'vagrant' logged in.")).toEqual(["It began. 'vagrant' logged in."]);
  });
});

describe("proseParagraphs", () => {
  const sentence = (n: number) =>
    `Sentence number ${n} says something about the host and its ${"x".repeat(60)}.`;

  it("leaves a short block as one paragraph", () => {
    expect(t.proseParagraphs("A short summary.")).toEqual(["A short summary."]);
  });

  it("keeps blank-line blocks exactly as the author split them", () => {
    expect(t.proseParagraphs("First para.\n\n  \nSecond para.")).toEqual(["First para.", "Second para."]);
  });

  // A block with line structure is a list or a hand-typed narrative. Re-splitting it at sentence
  // ends would destroy the shape its author chose, so length is not even consulted.
  it("never splits a block that already has line breaks in it", () => {
    const list = `- ${"a".repeat(300)}\n- ${"b".repeat(300)}`;
    expect(t.proseParagraphs(list)).toEqual([list]);
  });

  it("splits a long undivided block at sentence ends", () => {
    const paras = t.proseParagraphs([1, 2, 3, 4, 5, 6].map(sentence).join(" "));
    expect(paras.length).toBeGreaterThan(1);
    for (const p of paras) expect(p).toMatch(/\.$/);
  });

  // THE INVARIANT THAT MATTERS. Every word survives the split, in order — this is prose an analyst
  // will paste into a report, and a transform that quietly drops a clause is worse than a wall.
  it("loses no text", () => {
    const src = [1, 2, 3, 4, 5, 6, 7].map(sentence).join(" ");
    expect(t.proseParagraphs(src).join(" ")).toBe(src);
  });

  it("folds a short tail into the paragraph before it rather than leaving an orphan", () => {
    const paras = t.proseParagraphs(`${sentence(1)} ${sentence(2)} ${sentence(3)} ${sentence(4)} Short.`);
    expect(paras[paras.length - 1]).not.toBe("Short.");
    expect(paras[paras.length - 1]).toMatch(/ Short\.$/);
  });

  // …but only into a paragraph THIS block produced. A tail folded across a blank line would move
  // text the author had deliberately separated into the wrong paragraph.
  it("never folds a tail into a paragraph from an earlier block", () => {
    expect(t.proseParagraphs("Author's own first block.\n\nShort.")).toEqual([
      "Author's own first block.",
      "Short.",
    ]);
  });

  it("renders nothing for nothing", () => {
    expect(t.proseParagraphs("")).toEqual([]);
    expect(t.proseParagraphs(null)).toEqual([]);
    expect(t.proseParagraphs("   \n\n  ")).toEqual([]);
  });
});

// A deliberately small markdown subset — headings, both list flavours, bold and code — used for AI
// narrative output. Everything is escaped BEFORE any markup is added, which is the ordering that
// matters: the source is model output rendered with innerHTML.
describe("mdToHtml", () => {
  it("renders headings one level down, capped at h5", () => {
    expect(t.mdToHtml("# Title")).toBe("<h2>Title</h2>");
    expect(t.mdToHtml("###### Deep")).toBe("<h5>Deep</h5>");
  });

  it("renders both list flavours and closes them", () => {
    expect(t.mdToHtml("- a\n- b")).toBe("<ul><li>a</li><li>b</li></ul>");
    expect(t.mdToHtml("1. a\n2. b")).toBe("<ol><li>a</li><li>b</li></ol>");
  });

  it("closes one list before opening another", () => {
    expect(t.mdToHtml("- a\n1. b")).toBe("<ul><li>a</li></ul><ol><li>b</li></ol>");
  });

  it("renders inline bold and code", () => {
    expect(t.mdToHtml("**b** and `c`")).toBe("<p><strong>b</strong> and <code>c</code></p>");
  });

  it("escapes the source before adding any markup", () => {
    expect(t.mdToHtml("<img src=x onerror=alert(1)>")).toBe("<p>&lt;img src=x onerror=alert(1)&gt;</p>");
    expect(t.mdToHtml("**<b>**")).toBe("<p><strong>&lt;b&gt;</strong></p>");
  });

  it("renders nothing for nothing", () => {
    expect(t.mdToHtml("")).toBe("");
    expect(t.mdToHtml(null)).toBe("");
  });
});

describe("egShortHost", () => {
  it("strips the scheme, port, path and domain suffix", () => {
    expect(t.egShortHost("HTTPS://Sub.Example.com:8443/path?q=1")).toBe("sub");
    expect(t.egShortHost("wkstn-04.corp.local")).toBe("wkstn-04");
  });

  it("returns an empty string for nothing", () => {
    expect(t.egShortHost(null)).toBe("");
  });
});

describe("arrayBufferToBase64", () => {
  it("encodes a buffer", () => {
    expect(t.arrayBufferToBase64(new TextEncoder().encode("hello").buffer)).toBe("aGVsbG8=");
    expect(t.arrayBufferToBase64(new ArrayBuffer(0))).toBe("");
  });

  // Chunked at 32 KB because String.fromCharCode.apply blows the argument limit on a large
  // buffer — the failure mode is a RangeError on exactly the big evidence files this is for.
  it("handles a buffer larger than one 32 KB chunk", () => {
    const bytes = new Uint8Array(70_000).fill(65);
    expect(t.arrayBufferToBase64(bytes.buffer)).toBe(Buffer.from(bytes).toString("base64"));
  });
});

describe("custodyGroupByArtifact", () => {
  it("groups records by path, preserving order within each group", () => {
    const grouped = t.custodyGroupByArtifact([
      { artifactPath: "a", n: 1 },
      { artifactPath: "b", n: 2 },
      { artifactPath: "a", n: 3 },
    ]);
    expect([...grouped.keys()]).toEqual(["a", "b"]);
    expect(grouped.get("a")?.map((r) => r.n)).toEqual([1, 3]);
  });
});

// Command-shape prevalence: reduce a command line to its shape so "the same command with different
// arguments" counts once across hosts. This is the piece that makes "seen on 1 host" meaningful.
describe("clientCommandShape", () => {
  it.each([
    ["a hash", "check d41d8cd98f00b204e9800998ecf8427e", "check <hash>"],
    ["a GUID", "svc {6B29FC40-CA47-1067-B31D-00DD010662DA}", "svc <guid>"],
    ["a UNC path", "copy \\\\server\\share\\f", "copy <unc>"],
    ["a drive path", "run c:\\windows\\system32\\x.exe", "run <path>"],
    ["a posix path", "run /usr/local/bin/x", "run <path>"],
    ["a quoted string", 'echo "hello world"', "echo <str>"],
    ["a number", "sleep 3600", "sleep <n>"],
  ])("replaces %s", (_label, input, expected) => expect(t.clientCommandShape(input)).toBe(expected));

  it("collapses whitespace, lowercases and caps the shape at 200 characters", () => {
    expect(t.clientCommandShape("  CMD   /C   x  ")).toBe("cmd /c x");
    expect(t.clientCommandShape("x".repeat(300))).toHaveLength(200);
  });

  it("makes two runs of the same command with different arguments one shape", () => {
    expect(t.clientCommandShape("net use \\\\a\\b /user:x")).toBe(
      t.clientCommandShape("net use \\\\c\\d /user:x"),
    );
  });
});

describe("clientPatternKey", () => {
  it("prefers a hash over everything else", () => {
    expect(t.clientPatternKey({ sha256: "AB", processName: "cmd.exe", description: "x" })).toBe("hash:ab");
    expect(t.clientPatternKey({ md5: "CD" })).toBe("hash:cd");
  });

  it("falls back to process plus command shape, then to the shape alone", () => {
    expect(t.clientPatternKey({ processName: "CMD.exe", description: "cmd /c 1" })).toBe(
      "proc:cmd.exe|cmd /c <n>",
    );
    expect(t.clientPatternKey({ description: "cmd /c 1" })).toBe("desc:cmd /c <n>");
  });

  it("returns an empty key for an event with nothing to fingerprint", () => {
    expect(t.clientPatternKey({})).toBe("");
  });
});

describe("buildClientPrevalence", () => {
  it("counts occurrences and distinct hosts, case-insensitively", () => {
    const idx = t.buildClientPrevalence([
      { description: "cmd /c 1", asset: "H1" },
      { description: "cmd /c 2", asset: "h1" },
      { description: "cmd /c 3", asset: "H2" },
    ]);
    const entry = idx.get("desc:cmd /c <n>");
    expect(entry?.count).toBe(3);
    expect([...(entry?.hosts ?? [])]).toEqual(["h1", "h2"]);
  });

  it("skips events with no fingerprint rather than bucketing them together", () => {
    expect(t.buildClientPrevalence([{}, {}]).size).toBe(0);
    expect(t.buildClientPrevalence(null).size).toBe(0);
  });

  it("records a hashed event with no asset as a host-less occurrence", () => {
    const entry = t.buildClientPrevalence([{ sha256: "ab" }]).get("hash:ab");
    expect(entry?.count).toBe(1);
    expect(entry?.hosts.size).toBe(0);
  });
});
