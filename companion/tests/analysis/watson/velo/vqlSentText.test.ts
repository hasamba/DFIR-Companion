import { describe, it, expect } from "vitest";
import { vqlAllowed } from "../../../../src/analysis/ai/watson/velo/vqlAllowed.js";
import { checkLaunch } from "../../../../src/analysis/ai/watson/velo/launchCheck.js";
import { deployHuntBodyProblem } from "../../../../src/routes/huntDeployBody.js";
import { matchClient } from "../../../../src/integrations/velociraptor/clientInventory.js";

// Final-review G1-G3: the text Watson checks must be the text Velociraptor runs. The launch path
// splits on blank lines, drops `--` lines and wraps the artifact in '''…''', so any of those inside
// a string or comment would let the checked text and the run text disagree.

const ctx = { inventory: [], deployed: new Set<string>(), matchClient };
const hunt = (vql: string) => checkLaunch({ vql, mode: "hunt" }, ctx);
const blocked = (vql: string): void => {
  expect(vqlAllowed(vql).ok, `expected blocked: ${JSON.stringify(vql)}`).toBe(false);
  expect(hunt(vql).ok, `expected launch refused: ${JSON.stringify(vql)}`).toBe(false);
};

describe("G1 — a blank line or `--` line inside a string never splits the run text", () => {
  it("refuses the split-desync payload", () => {
    blocked("SELECT 'a\n-- '\nAS A, ' FROM info()\n\nSELECT * FROM execve(argv=[\"calc\"])\n\n-- '");
  });

  it("refuses a blank line inside a string literal", () => {
    blocked("SELECT 'a\n\nb' AS A FROM info()");
    blocked("SELECT 'a\n   \nb' AS A FROM info()");
  });

  it("refuses a line that starts with -- inside a string literal", () => {
    blocked("SELECT 'a\n  -- b' AS A FROM info()");
  });

  it("still allows two statements separated by a blank line", () => {
    expect(hunt("SELECT * FROM pslist()\n\nSELECT * FROM info()").ok).toBe(true);
  });
});

describe("G2 — ''' never reaches the server-side wrapper", () => {
  const payload = "SELECT '''\nLET Y <= SELECT * FROM execve(argv=[\"id\"])\nLET Z = ''' AS A FROM info()";

  it("refuses the wrapper breakout in Watson's check", () => {
    blocked(payload);
    blocked("SELECT '''x''' AS A FROM info()");
  });

  it("refuses it on the analyst and bundle deploy path too", () => {
    expect(deployHuntBodyProblem({ vql: payload, title: "t", mode: "hunt", hostname: "" })).toMatch(/'''/);
    expect(
      deployHuntBodyProblem({ vql: "SELECT * FROM pslist()", title: "t", mode: "hunt", hostname: "" }),
    ).toBeNull();
  });
});

describe("G3 — comments and carriage returns are refused in launch VQL", () => {
  it("refuses the // comment-sandwich form", () => {
    blocked("SELECT 2 //**/ 1 AS Y, execve(argv=['x']) AS X FROM info()");
  });

  it("refuses a -- comment", () => {
    blocked("SELECT 2 --1\nAS Y FROM info()");
    blocked("SELECT * FROM pslist() -- note");
  });

  it("refuses a block comment", () => {
    blocked("SELECT /* note */ * FROM pslist()");
  });

  it("refuses a lone carriage return anywhere", () => {
    blocked("SELECT * FROM pslist()\r");
    blocked("SELECT 'a\rb' AS A FROM info()");
  });

  it("does not treat -- or // inside a one-line string as a comment", () => {
    expect(vqlAllowed("SELECT * FROM pslist() WHERE Name = 'a--b//c'")).toEqual({ ok: true });
  });
});

describe("the prompt teaches the shape rules", () => {
  it("tells the model not to use comments or triple quotes", async () => {
    const { veloRulesText } = await import("../../../../src/analysis/ai/watson/velo/veloPrompt.js");
    expect(veloRulesText()).toContain("No comments of any kind");
    expect(veloRulesText()).toContain("no triple-quoted strings");
  });
});

describe("the prompt tells the truth about approval in both modes (G9)", () => {
  it("says a fleet hunt always waits and a collection may launch in Auto", async () => {
    const { veloRulesText } = await import("../../../../src/analysis/ai/watson/velo/veloPrompt.js");
    const t = veloRulesText();
    expect(t).not.toContain("The analyst approves it first.");
    expect(t).toContain("A fleet hunt always waits for the analyst's approval");
    expect(t).toContain("unless the\ncase is in Auto mode");
  });
});

describe("I-1 — line-breaking and invisible characters are refused anywhere", () => {
  const seps = { "U+2028": " ", "U+2029": " ", "U+0085": "\u0085" };
  for (const [name, ch] of Object.entries(seps)) {
    it(`refuses ${name} inside a string, in the launch check and the deploy body check`, () => {
      const vql = `SELECT 'a${ch}  - name: X' AS A FROM info()`;
      expect(hunt(vql).ok).toBe(false);
      expect(deployHuntBodyProblem({ vql, title: "t", mode: "hunt", hostname: "" })).toMatch(/character/);
    });
  }

  it("refuses other control and zero-width characters", () => {
    for (const ch of ["\u0001", "\u007f", "\u009b", "​", "‍", "﻿", "\r"]) {
      expect(hunt(`SELECT 'a${ch}b' AS A FROM info()`).ok, JSON.stringify(ch)).toBe(false);
    }
  });

  it("still allows a normal non-ASCII letter in a string", () => {
    const vql = "SELECT * FROM pslist() WHERE Name = 'café'";
    expect(hunt(vql).ok).toBe(true);
    expect(deployHuntBodyProblem({ vql, title: "t", mode: "hunt", hostname: "" })).toBeNull();
  });
});
