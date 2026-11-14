import { describe, expect, it } from "vitest";
import { checkLaunch } from "../../../../src/analysis/ai/watson/velo/launchCheck.js";
import { tokenizeVql } from "../../../../src/analysis/ai/watson/velo/vqlTokens.js";
import { classifyReason } from "../../../../src/analysis/ai/watson/velo/vqlRiskClass.js";
import {
  sanitizeVqlDurations,
  splitVqlStatements,
  unsafeVqlCharProblem,
} from "../../../../src/analysis/vqlStatements.js";
import { deployHuntBodyProblem } from "../../../../src/routes/huntDeployBody.js";
import { matchClient } from "../../../../src/integrations/velociraptor/clientInventory.js";

// Task 9 fix round 1 (review I-1, I-2): the text the analyst reads on a risky card is the text that
// runs. Invisible format characters are HARD everywhere; the duration rewrite never touches strings.

const ctx = { inventory: [], deployed: new Set<string>(), matchClient, allowRisky: true };
const hunt = (vql: string) => checkLaunch({ vql, mode: "hunt" }, ctx);

const INVISIBLE: Array<[string, string]> = [
  ["RLO bidi override", "\u202E"],
  ["LRE", "\u202A"],
  ["PDF", "\u202C"],
  ["LRI isolate", "\u2066"],
  ["PDI isolate", "\u2069"],
  ["LRM", "\u200E"],
  ["RLM", "\u200F"],
  ["soft hyphen", "\u00AD"],
  ["word joiner", "\u2060"],
  ["invisible plus", "\u2064"],
  ["Mongolian vowel separator", "\u180E"],
  ["Hangul choseong filler", "\u115F"],
  ["Hangul jungseong filler", "\u1160"],
  ["Hangul filler", "\u3164"],
  ["halfwidth Hangul filler", "\uFFA0"],
  ["variation selector 16", "\uFE0F"],
  ["variation selector 1", "\uFE00"],
  ["variation selector supplement", "\u{E0100}"],
  ["variation selector supplement end", "\u{E01EF}"],
  ["tag character", "\u{E0041}"],
];

describe("invisible format characters are HARD everywhere (I-1)", () => {
  it.each(INVISIBLE)("%s inside an argv string is refused and not approvable", (_n, ch) => {
    const vql = `SELECT * FROM execve(argv=['cmd.exe','/c','${ch}exe.txt'])`;
    const r = hunt(vql);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reasons?.some((x) => classifyReason(x) === "hard")).toBe(true);
    expect(unsafeVqlCharProblem(vql)).toMatch(/U\+[0-9A-F]{4,6}/);
    expect(deployHuntBodyProblem({ vql, title: "t", mode: "hunt", hostname: "" })).not.toBeNull();
  });

  it("the review's RLO case is refused even with allowRisky", () => {
    expect(hunt("SELECT * FROM execve(argv=['cmd.exe','/c','\u202Eexe.txt'])").ok).toBe(false);
  });

  it.each(["café", "東京", "Ärger", "naïve", "😀"])(
    "normal non-ASCII text %s inside a string stays allowed",
    (w) => {
      const vql = `SELECT * FROM pslist() WHERE Name = '${w}'`;
      expect(unsafeVqlCharProblem(vql)).toBeNull();
      expect(hunt(vql)).toMatchObject({ ok: true });
    },
  );
});

const stringTexts = (vql: string): string[] => {
  const t = tokenizeVql(vql);
  return t.ok ? t.tokens.filter((x) => x.kind === "string").map((x) => x.text) : ["<untokenizable>"];
};

describe("the duration rewrite never changes a string literal (I-2)", () => {
  const REVIEW = `SELECT * FROM execve(argv=["cmd.exe","/c","del /q C:/Users/Public/report-1h"])`;

  it("leaves the review's argv string byte-identical", () => {
    expect(sanitizeVqlDurations(REVIEW)).toBe(REVIEW);
  });

  it("still rewrites durations outside strings, and only there", () => {
    const vql = "SELECT * FROM pslist() WHERE Start > now() - 7d AND Name = 'x-1h' AND P = \"y+2d\"";
    expect(sanitizeVqlDurations(vql)).toBe(
      "SELECT * FROM pslist() WHERE Start > now() - 7 * 86400 AND Name = 'x-1h' AND P = \"y+2d\"",
    );
  });

  it("a quote inside a comment does not hide a later duration from the rewrite", () => {
    expect(sanitizeVqlDurations("-- don't\nSELECT now() - 2h FROM scope()")).toBe(
      "-- don't\nSELECT now() - 2 * 3600 FROM scope()",
    );
  });

  it("triple-quoted and escaped strings are left alone", () => {
    expect(sanitizeVqlDurations("SELECT '''a-1h''' FROM scope()")).toBe("SELECT '''a-1h''' FROM scope()");
    expect(sanitizeVqlDurations('SELECT "a\\"-1h" FROM scope()')).toBe('SELECT "a\\"-1h" FROM scope()');
  });

  it("the string tokens Velociraptor receives equal the stored VQL's, for an approvable launch", () => {
    const vql = `SELECT * FROM execve(argv=['cmd.exe','/c','del /q C:/Users/Public/report-1h']) WHERE now() - 1d > 0`;
    expect(hunt(vql)).toMatchObject({ ok: true });
    const sent = splitVqlStatements(sanitizeVqlDurations(vql)).join("\n\n");
    expect(stringTexts(sent)).toEqual(stringTexts(vql));
  });
});

describe("reason rules for the new refusals", () => {
  it("an astral invisible character's reason (U+E0100, six digits) is named by a HARD rule", async () => {
    const { ruleFor } = await import("../../../../src/analysis/ai/watson/velo/vqlRiskClass.js");
    const reason = unsafeVqlCharProblem("x\u{E0100}") ?? "";
    expect(reason).toContain("U+E0100");
    expect(ruleFor(reason)?.cls).toBe("hard");
  });
});
