import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { getWatsonPrompt } from "../../../src/analysis/ai/prompts/index.js";
import { WATSON_PROMPT } from "../../../src/analysis/ai/prompts/watson.js";

// Task 10, the user's decision of 2026-11-14: "i want the entire watson chat will be in asd-ste100
// standard". The prompt tells Watson to write in ASD-STE100, and the fixed notes the server adds to
// the chat keep to its sentence limit (25 words for a descriptive sentence).

describe("WATSON_PROMPT: the ASD-STE100 rule", () => {
  it("tells Watson to write every analyst-facing field in ASD-STE100, with the sentence limits", () => {
    expect(WATSON_PROMPT).toContain("ASD-STE100 (Simplified Technical English)");
    for (const field of [
      "'message'",
      "'workingOn'",
      "'learned'",
      "'answer'",
      "'pointer'",
      "'why'",
      "'title'",
    ]) {
      expect(WATSON_PROMPT).toContain(field);
    }
    expect(WATSON_PROMPT).toContain("findings, next steps and report fields");
    expect(WATSON_PROMPT).toContain("procedural sentence (an instruction) in 20 words or fewer");
    expect(WATSON_PROMPT).toContain("descriptive sentence in 25 words or fewer");
    expect(WATSON_PROMPT).toContain("only one instruction in each sentence. Use the active voice");
    expect(WATSON_PROMPT).toContain("approved words in their approved meanings");
    expect(WATSON_PROMPT).toContain("Do not use idioms, slang or contractions");
  });

  it("keeps technical names, quoted evidence and queries verbatim", () => {
    expect(WATSON_PROMPT).toMatch(
      /Keep technical names exactly as they are: host names, user names, paths, hashes/,
    );
    expect(WATSON_PROMPT).toContain("Keep quoted evidence exactly as it is");
    expect(WATSON_PROMPT).toMatch(
      /'query', 'vql', search 'terms' and 'lookup' values are not text for the analyst/,
    );
  });

  it("is in the built-in prompt the round sends", () => {
    expect(getWatsonPrompt()).toContain("ASD-STE100");
  });
});

// ── The fixed chat notes: a simple lint over the string literals of the Watson server code ─────

const SRC = join(__dirname, "../../../src");
const WATSON_DIR = join(SRC, "analysis/ai/watson");
/** Chat-visible notes written outside the Watson folder. */
const EXTRA_FILES = [
  "composition/watsonCaseEvents.ts",
  "composition/watsonVeloResults.ts",
  "routes/watson.ts",
  "routes/watsonPasteIngest.ts",
  "routes/watsonSlash.ts",
];
/** Model-facing prompt text (not shown in the chat), and VQL name lists. */
const SKIP = new Set(["promptBuilder.ts", "velo/veloPrompt.ts", "velo/vqlAllowlist.ts"]);
const MAX_WORDS = 25;

function tsFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return tsFiles(path);
    return name.endsWith(".ts") ? [path] : [];
  });
}

/** The literal text of a string, a template (each `${…}` read as one word) or a `+` join of them. */
function textOf(node: ts.Node): string | null {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isTemplateExpression(node)) {
    return node.head.text + node.templateSpans.map((s) => `X${s.literal.text}`).join("");
  }
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = textOf(node.left);
    const right = textOf(node.right);
    return left !== null && right !== null ? left + right : null;
  }
  if (ts.isParenthesizedExpression(node)) return textOf(node.expression);
  return null;
}

function literals(file: string): string[] {
  const source = ts.createSourceFile(file, readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true);
  const out: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) return;
    const text = textOf(node);
    if (text !== null) {
      out.push(text);
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return out;
}

/** Prose only: two or more words that start with a capital letter or "(". */
const isProse = (s: string): boolean => /^\(?[A-Z][a-z']*\s/.test(s.trim());

/** Sentences longer than the limit, split simply at ". ", "? ", "! " and new lines. */
function longSentences(text: string, max = MAX_WORDS): string[] {
  return text
    .split(/(?<=[.?!])\s+|\n+/)
    .map((s) => s.trim())
    .filter((s) => s.split(/\s+/).filter(Boolean).length > max);
}

describe("fixed Watson chat notes stay within the ASD-STE100 sentence limit", () => {
  it("the splitter finds a long sentence and passes short ones", () => {
    expect(longSentences("One two three. Four five.")).toEqual([]);
    const long = Array.from({ length: 26 }, (_, i) => `w${i}`).join(" ");
    expect(longSentences(`Short one. ${long}.`)).toEqual([`${long}.`]);
  });

  const files = [...tsFiles(WATSON_DIR), ...EXTRA_FILES.map((f) => join(SRC, f))].filter(
    (f) => !SKIP.has(relative(WATSON_DIR, f).replace(/\\/g, "/")),
  );

  it("reads the Watson server files", () => {
    expect(files.length).toBeGreaterThan(30);
  });

  it(`every sentence in a fixed note has ${MAX_WORDS} words or fewer`, () => {
    const offenders = files.flatMap((f) =>
      literals(f)
        .filter(isProse)
        .flatMap((s) => longSentences(s))
        .map((s) => `${relative(SRC, f)}: ${s}`),
    );
    expect(offenders).toEqual([]);
  });
});

describe("the Watson card strings in public/js stay within the ASD-STE100 sentence limit", () => {
  const view = join(SRC, "../../public/js/dashboard-watson-view.js");

  it("every prose sentence in the card builders has 25 words or fewer", () => {
    const offenders = literals(view)
      .filter(isProse)
      .flatMap((s) => longSentences(s));
    expect(offenders).toEqual([]);
  });

  it("the new lookup lines were read", () => {
    const all = literals(view).join("\n");
    expect(all).toContain("Watson searched the pasted file:");
    expect(all).toContain("super-timeline searches for this question.");
  });
});
