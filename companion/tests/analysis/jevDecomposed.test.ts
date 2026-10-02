import { describe, it, expect } from "vitest";
import {
  DECOMPOSED_RULE,
  buildAnalystContext,
  buildDecomposedQuestions,
  decideSeverity,
  readDecomposedAnswers,
  type DecomposedSignals,
} from "../../src/analysis/ai/jev/jevDecomposed.js";
import type { JevAnswer } from "../../src/analysis/ai/jev/jevClient.js";
import type { FalsePositiveMarker } from "../../src/analysis/falsePositive.js";

const SEVERITIES = ["Info", "Low", "Medium", "High", "Critical"] as const;
const rank = (g: string) => SEVERITIES.indexOf(g as (typeof SEVERITIES)[number]);

function sig(over: Partial<DecomposedSignals> = {}): DecomposedSignals {
  return {
    malicious: 0,
    explained: null,
    strength: 0,
    strengthConfidence: 1,
    impact: 0,
    ...over,
  };
}

describe("decideSeverity — the table", () => {
  it.each([
    // malicious, strength, impact, expected
    [0.1, 0.5, 0, "Info"],
    [0.1, 1.2, 0, "Low"],
    [0.1, 2.0, 0, "Low"],
    [0.1, 2.8, 3, "Medium"],
    [0.5, 0.5, 0, "Low"],
    [0.5, 1.2, 0, "Low"],
    [0.5, 2.0, 0, "Medium"],
    [0.5, 2.8, 3, "High"],
    [0.9, 0.5, 0, "Medium"],
    [0.9, 1.2, 0, "Medium"],
    [0.9, 2.0, 0, "High"],
    [0.9, 2.8, 0, "High"],
    [0.9, 2.8, 3, "Critical"],
  ])("malicious %s, strength %s, impact %s → %s", (m, s, i, expected) => {
    expect(decideSeverity(sig({ malicious: m, strength: s, impact: i })).grade).toBe(expected);
  });

  it("puts the band edges on the documented side", () => {
    expect(decideSeverity(sig({ malicious: 0.4, strength: 2.5 })).grade).toBe("High");
    expect(decideSeverity(sig({ malicious: 0.39, strength: 2.5 })).grade).toBe("Medium");
    expect(decideSeverity(sig({ malicious: 0.75, strength: 2.5, impact: 2.5 })).grade).toBe("Critical");
    expect(decideSeverity(sig({ malicious: 0.749, strength: 2.5, impact: 3 })).grade).toBe("High");
    expect(decideSeverity(sig({ malicious: 0.9, strength: 1.5 })).grade).toBe("High");
    expect(decideSeverity(sig({ malicious: 0.9, strength: 1.49 })).grade).toBe("Medium");
  });

  it("never gives Critical without high impact, however sure and strong", () => {
    expect(decideSeverity(sig({ malicious: 1, strength: 3, impact: 2.49 })).grade).toBe("High");
  });

  it("never jumps more than one level across any band edge (no cliff)", () => {
    const ms = [0, 0.2, 0.39, 0.4, 0.6, 0.749, 0.75, 0.9, 1];
    const ss = [0, 0.5, 0.99, 1, 1.49, 1.5, 2, 2.49, 2.5, 3];
    for (let a = 0; a < ms.length - 1; a++)
      for (const s of ss) {
        const lo = rank(decideSeverity(sig({ malicious: ms[a], strength: s })).grade);
        const hi = rank(decideSeverity(sig({ malicious: ms[a + 1], strength: s })).grade);
        expect(hi - lo).toBeGreaterThanOrEqual(0);
        expect(hi - lo).toBeLessThanOrEqual(1);
      }
    for (const m of ms)
      for (let b = 0; b < ss.length - 1; b++) {
        const lo = rank(decideSeverity(sig({ malicious: m, strength: ss[b] })).grade);
        const hi = rank(decideSeverity(sig({ malicious: m, strength: ss[b + 1] })).grade);
        expect(hi - lo).toBeGreaterThanOrEqual(0);
        expect(hi - lo).toBeLessThanOrEqual(1);
      }
  });

  it("is monotone: more malicious or stronger evidence never lowers the grade", () => {
    for (let i = 0; i < 400; i++) {
      const m = ((i * 37) % 101) / 100;
      const s = ((i * 53) % 31) / 10;
      const imp = ((i * 11) % 31) / 10;
      const base = rank(decideSeverity(sig({ malicious: m, strength: s, impact: imp })).grade);
      const moreM = rank(
        decideSeverity(sig({ malicious: Math.min(1, m + 0.1), strength: s, impact: imp })).grade,
      );
      const moreS = rank(
        decideSeverity(sig({ malicious: m, strength: Math.min(3, s + 0.3), impact: imp })).grade,
      );
      expect(moreM).toBeGreaterThanOrEqual(base);
      expect(moreS).toBeGreaterThanOrEqual(base);
    }
  });
});

describe("decideSeverity — analyst records", () => {
  it("an analyst record that explains a quiet row grades it Info, decision explained", () => {
    const d = decideSeverity(sig({ malicious: 0.2, strength: 1.2, explained: 0.9 }));
    expect(d.grade).toBe("Info");
    expect(d.decision).toBe("explained");
  });

  it("a record that explains a row the model calls malicious is a CONFLICT, never silent Info", () => {
    const d = decideSeverity(sig({ malicious: 0.8, strength: 2.8, impact: 3, explained: 0.95 }));
    expect(d.decision).toBe("conflict");
    expect(d.grade).toBe("Medium");
  });

  it("strong evidence against a record is a conflict too, even at low malicious", () => {
    const d = decideSeverity(sig({ malicious: 0.3, strength: 2.2, explained: 0.99 }));
    expect(d.decision).toBe("conflict");
    expect(d.grade).toBe("Medium");
  });

  it("a weak explained answer never silently wipes out a strong grade — it is a conflict", () => {
    const d = decideSeverity(sig({ malicious: 0.99, strength: 3, impact: 3, explained: 0.55 }));
    expect(d.decision).toBe("conflict");
    expect(d.grade).toBe("Medium");
  });

  it("is monotone in explained: a stronger analyst record never raises the grade", () => {
    const es = [0, 0.2, 0.49, 0.5, 0.55, 0.6, 0.8, 1];
    for (const m of [0, 0.3, 0.5, 0.7, 0.9, 1])
      for (const s of [0, 1, 1.6, 2.2, 3])
        for (let k = 0; k < es.length - 1; k++) {
          const lo = rank(
            decideSeverity(sig({ malicious: m, strength: s, impact: 3, explained: es[k] })).grade,
          );
          const hi = rank(
            decideSeverity(sig({ malicious: m, strength: s, impact: 3, explained: es[k + 1] })).grade,
          );
          // A conflict pins Medium, which can sit ABOVE a quiet row's Info/Low: that is the point —
          // a record that disputes evidence must be looked at. It never lifts a row past Medium.
          if (hi > lo) expect(hi).toBe(2);
        }
  });

  it("explained null (not asked) changes nothing", () => {
    expect(decideSeverity(sig({ malicious: 0.9, strength: 2 })).decision).toBe("graded");
  });
});

describe("decideSeverity — confidence and score", () => {
  it("confidence is the weaker of the decisive noul's certainty and the strength confidence", () => {
    expect(
      decideSeverity(sig({ malicious: 0.9, strength: 2, strengthConfidence: 0.95 })).confidence,
    ).toBeCloseTo(0.9);
    expect(
      decideSeverity(sig({ malicious: 0.9, strength: 2, strengthConfidence: 0.6 })).confidence,
    ).toBeCloseTo(0.6);
    expect(
      decideSeverity(sig({ malicious: 0.2, strength: 0, strengthConfidence: 1 })).confidence,
    ).toBeCloseTo(0.8);
  });

  it("uses the explained noul's certainty on the explained branch", () => {
    const d = decideSeverity(sig({ malicious: 0.1, explained: 0.7, strengthConfidence: 1 }));
    expect(d.confidence).toBeCloseTo(0.7);
  });

  it("keeps the score inside its level, so rounding the score gives the grade back", () => {
    for (let i = 0; i < 200; i++) {
      const d = decideSeverity(
        sig({ malicious: (i % 11) / 10, strength: (i % 7) / 2, impact: (i % 5) * 0.75 }),
      );
      expect(Math.round(d.score)).toBe(rank(d.grade));
      expect(d.score).toBeGreaterThanOrEqual(rank(d.grade));
      expect(d.score).toBeLessThan(rank(d.grade) + 0.5);
    }
  });

  it("clamps out-of-contract values instead of trusting them", () => {
    const d = decideSeverity(sig({ malicious: 7, strength: 99, impact: -4, strengthConfidence: 3 }));
    expect(d.grade).toBe("High");
    expect(d.confidence).toBeLessThanOrEqual(1);
    expect(d.score).toBeLessThan(4);
    expect(decideSeverity(sig({ malicious: -1, strength: -5 })).grade).toBe("Info");
  });
});

describe("buildDecomposedQuestions", () => {
  it("asks malicious, strength and impact about the full row view, keyed per row", () => {
    const q = buildDecomposedQuestions(["R000"], { withContext: false });
    expect(Object.keys(q).sort()).toEqual(["R000_imp", "R000_mal", "R000_str"]);
    expect(q.R000_mal.type).toBe("noul");
    expect(q.R000_str.type).toBe("score");
    expect(q.R000_imp.type).toBe("score");
    for (const k of Object.keys(q)) expect(q[k].instructions).toContain("`R000` in `rows`");
  });

  it("asks the explained question only when there is analyst context, and points it at caseContext", () => {
    const q = buildDecomposedQuestions(["R000"], { withContext: true });
    expect(q.R000_exp.type).toBe("noul");
    expect(q.R000_exp.instructions).toContain("caseContext");
  });

  it("uses 4 ordered levels for both scores", () => {
    const q = buildDecomposedQuestions(["R001"], { withContext: false });
    if (q.R001_str.type !== "score" || q.R001_imp.type !== "score") throw new Error("not scores");
    expect(q.R001_str.criteria).toHaveLength(4);
    expect(q.R001_imp.criteria).toHaveLength(4);
  });
});

describe("readDecomposedAnswers", () => {
  const score = (v: number, c = 0.8): JevAnswer => ({
    type: "score",
    score: v,
    legend: {},
    probabilities: {},
    confidence: c,
  });
  const noul = (p: number): JevAnswer => ({ type: "noul", noul: p });

  it("reads every signal, explained null when not asked", () => {
    const s = readDecomposedAnswers(
      { R000_mal: noul(0.8), R000_str: score(2.1, 0.7), R000_imp: score(1) },
      "R000",
      false,
    );
    expect(s).toEqual({ malicious: 0.8, explained: null, strength: 2.1, strengthConfidence: 0.7, impact: 1 });
  });

  it.each(["R000_mal", "R000_str", "R000_imp", "R000_exp"])("throws when %s is missing", (missing) => {
    const all: Record<string, JevAnswer> = {
      R000_mal: noul(0.8),
      R000_str: score(2),
      R000_imp: score(1),
      R000_exp: noul(0.1),
    };
    delete all[missing];
    expect(() => readDecomposedAnswers(all, "R000", true)).toThrow(/R000/);
  });

  it("throws when an answer comes back with the wrong type", () => {
    expect(() =>
      readDecomposedAnswers({ R000_mal: score(1), R000_str: score(2), R000_imp: score(1) }, "R000", false),
    ).toThrow(/R000/);
  });

  it("names the rule version the decision was made under", () => {
    expect(DECOMPOSED_RULE).toBe("d1");
  });
});

describe("buildAnalystContext", () => {
  const marker = (over: Partial<FalsePositiveMarker>): FalsePositiveMarker => ({
    id: "x",
    kind: "ioc",
    ref: "psexec.exe",
    reason: "authorized-test",
    note: "red team week",
    markedAt: "2026-01-01T00:00:00Z",
    markedBy: "a",
    ...over,
  });

  it("is empty when the analyst has recorded nothing, so the explained question is never asked", () => {
    expect(buildAnalystContext([], (t) => t)).toBe("");
  });

  it("lists finding and IOC records, masked, and leaves event markers out", () => {
    const out = buildAnalystContext(
      [marker({ ref: "SECRETHOST\\psexec.exe" }), marker({ kind: "event", ref: "evt-1" })],
      (t) => t.replaceAll("SECRETHOST", "ANON_HOST_1"),
    );
    expect(out).toContain("ANON_HOST_1\\psexec.exe");
    expect(out).toContain("authorized-test");
    expect(out).not.toContain("SECRETHOST");
    expect(out).not.toContain("evt-1");
  });

  it("leaves out the markers the automatic whitelist and NSRL sweeps wrote", () => {
    const out = buildAnalystContext(
      [
        marker({ ref: "aaa", reason: "known-good-tool", note: "auto-whitelist: exact notepad.exe" }),
        marker({ ref: "bbb", reason: "known-good-tool", note: "NSRL known-good hash (abc)" }),
        marker({ ref: "rclone.exe", note: "backup job, ticket 42" }),
      ],
      (t) => t,
    );
    expect(out).not.toContain("aaa");
    expect(out).not.toContain("bbb");
    expect(out).toContain("rclone.exe");
  });

  it("caps the length of each record and of the whole block", () => {
    const long = buildAnalystContext([marker({ note: "x".repeat(5000) })], (t) => t);
    expect(long.length).toBeLessThanOrEqual(240);
    const many = Array.from({ length: 40 }, (_, i) => marker({ ref: `t${i}`, note: "y".repeat(300) }));
    expect(buildAnalystContext(many, (t) => t).length).toBeLessThanOrEqual(4000);
  });

  it("caps how many records travel", () => {
    const many = Array.from({ length: 200 }, (_, i) => marker({ ref: `tool${i}.exe` }));
    expect(buildAnalystContext(many, (t) => t).split("\n").length).toBeLessThanOrEqual(40);
  });
});
