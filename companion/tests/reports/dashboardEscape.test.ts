import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// The esc() drift guard that public/js/dashboard-escape.js has always cited (#2882).
//
// esc() is duplicated on purpose -- dashboard-escape.js explains why it cannot simply be moved --
// and every copy feeds an innerHTML sink with adversary-controlled evidence. A copy that drifts
// (drops the apostrophe, the bidi markers, the null guard) is an XSS or a forged-looking row that
// no other test would notice. So this compiles EVERY copy out of the shipped source and runs the
// same hostile corpus through each, asserting each one matches the dashboard.html inline copy
// (the one that actually runs in the browser) plus absolute expectations, so all eight cannot
// drift together either.

type Escaper = (s: unknown) => string;

const read = (rel: string): string =>
  readFileSync(new URL(`../../../public/${rel}`, import.meta.url), "utf8");

// Index of the delimiter that closes the bracket opened at `open`. Naive about strings and regex
// literals, which is fine for these bodies: every bracket inside them is balanced.
function closingIndex(src: string, open: number): number {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (c === "{" || c === "(" || c === "[") depth++;
    else if (c === "}" || c === ")" || c === "]") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

// `function esc(s) { ... }` -- sliced by brace matching, because the bidi callback inside the body
// has its own braces and a first-`}` slice would truncate it.
function functionDecl(file: string, marker: string): string {
  const src = read(file);
  const start = src.indexOf(marker);
  if (start < 0) throw new Error(`esc not found in public/${file} (looked for "${marker}")`);
  const end = closingIndex(src, src.indexOf("{", start));
  if (end < 0) throw new Error(`unbalanced esc body in public/${file}`);
  return src.slice(start, end + 1);
}

// `const esc = s => ...;` -- an arrow expression, ending at the first `;` outside any bracket.
function arrowDecl(file: string, marker: string): string {
  const src = read(file);
  const start = src.indexOf(marker);
  if (start < 0) throw new Error(`esc not found in public/${file} (looked for "${marker}")`);
  let depth = 0;
  for (let i = start; i < src.length; i++) {
    const c = src[i];
    if (c === "{" || c === "(" || c === "[") depth++;
    else if (c === "}" || c === ")" || c === "]") depth--;
    else if (c === ";" && depth === 0) return src.slice(start, i + 1);
  }
  throw new Error(`esc arrow in public/${file} never ends`);
}

function compile(source: string, name: string): Escaper {
  // Compiling the shipped source is the point: a hand-copied escaper here could drift as well.
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(`${source}\nreturn ${name};`)() as Escaper;
}

const PALETTE_ESCAPES =
  'const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", \'"\': "&quot;", "\'": "&#39;" };';

// Every esc() under public/. A ninth copy belongs here; dashboard-bulk-findings.js's `const esc` is
// a regex escaper for a search term, a different function.
const COPIES: Record<string, () => string> = {
  "dashboard.html": () => functionDecl("dashboard.html", "function esc(s) {"),
  "js/dashboard-escape.js": () => functionDecl("js/dashboard-escape.js", "function esc(s) {"),
  "js/command-palette.js": () => {
    const src = read("js/command-palette.js");
    if (!src.includes(PALETTE_ESCAPES))
      throw new Error("ESCAPES table changed in public/js/command-palette.js");
    return `${PALETTE_ESCAPES}\n${functionDecl("js/command-palette.js", "function esc(s) {")}`;
  },
  "js/dashboard-text.js (mdToHtml)": () => arrowDecl("js/dashboard-text.js", "const esc = s =>"),
  "js/diagnostics-panel.js": () => functionDecl("js/diagnostics-panel.js", "function esc(s) {"),
  "present.html": () => functionDecl("present.html", "function esc(s) {"),
  "mobile.html": () => functionDecl("mobile.html", "function esc(s) {"),
  "admin.html": () => functionDecl("admin.html", "function esc(value) {"),
};

const BIDI = "‪‫‬‭‮⁦⁧⁨⁩";

const CORPUS: unknown[] = [
  `<a href="x" onclick='y'>&amp;</a>`,
  `"'"'`,
  `<img src=x onerror="alert('1')">`,
  BIDI,
  `invoice‮xcod.exe`,
  "&#39;&#x27;&#34;&lt;",
  "plain text",
  "",
  0,
  false,
  { toString: () => "<o>" },
  null,
  undefined,
];

const label = (v: unknown): string => (v === undefined ? "undefined" : JSON.stringify(v));

describe("esc drift guard (#2882)", () => {
  const reference = compile(COPIES["dashboard.html"](), "esc");

  it("the dashboard's own esc meets the absolute expectations", () => {
    expect(reference(`<a href="x" onclick='y'>&amp;</a>`)).toBe(
      "&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;amp;&lt;/a&gt;",
    );
    expect(reference(BIDI)).toBe(
      "&lt;LRE&gt;&lt;RLE&gt;&lt;PDF&gt;&lt;LRO&gt;&lt;RLO&gt;&lt;LRI&gt;&lt;RLI&gt;&lt;FSI&gt;&lt;PDI&gt;",
    );
    expect(reference("&#39;")).toBe("&amp;#39;");
    expect(reference(null)).toBe("");
    expect(reference(undefined)).toBe("");
    expect(reference(0)).toBe("0");
  });

  it.each(Object.keys(COPIES))("%s matches the dashboard.html copy on every hostile input", (name) => {
    const copy = compile(COPIES[name](), "esc");
    for (const input of CORPUS) {
      expect(copy(input), `${name} on ${label(input)}`).toBe(reference(input));
    }
  });
});

describe("escAttr drift guard (#2882)", () => {
  const withEscAttr = (file: string): Escaper =>
    compile(
      `${functionDecl(file, "function esc(s) {")}\n${functionDecl(file, "function escAttr(s) {")}`,
      "escAttr",
    );

  it("dashboard-escape.js's escAttr matches the dashboard.html copy", () => {
    const reference = withEscAttr("dashboard.html");
    const copy = withEscAttr("js/dashboard-escape.js");
    for (const input of CORPUS) {
      expect(copy(input), `escAttr on ${label(input)}`).toBe(reference(input));
    }
    expect(reference(`a"b'c`)).toBe("a&quot;b&#39;c");
  });
});
