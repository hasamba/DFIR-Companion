import { describe, expect, it } from "vitest";
import { expectLinearScan } from "../helpers/growth.js";
import {
  createAnonymizer,
  SECRET_PLACEHOLDER,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";
import { previewDiff, type PreviewDiff } from "../../src/analysis/ai/previewDiff.js";

// A fake PEM key, assembled at runtime so the repo's secret scan never sees key armor in source.
const [KEY_HEAD, KEY_TAIL] = ["BEGIN", "END"].map((edge) => `-----${edge} RSA PRIVATE KEY-----`);
const FAKE_RSA_KEY = `${KEY_HEAD}\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n${KEY_TAIL}`;

// #2531 — the preview's GitHub-style diff is built from the real anonymizer's own value→token map,
// lined up against the clear text without guessing.

function policy(maskPublicIps = true, over: Partial<AnonPolicy["categories"]> = {}): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps,
    categories: {
      IP: true,
      EMAIL: true,
      USER: true,
      HOST: true,
      DOMAIN: true,
      PATH: true,
      CMD: true,
      REG: true,
      CARD: true,
      PHONE: true,
      NATID: true,
      ...over,
    },
  };
}

const KNOWN: KnownEntities = {
  hosts: ["WS-FIN-07"],
  accounts: [],
  internalDomains: ["corp.example"],
  usernames: ["jdoe"],
  custom: [{ value: "Project Falcon", category: "OTHER" }],
};

function run(clear: string, pol = policy(), known = KNOWN): { masked: string; diff: PreviewDiff } {
  const anon = createAnonymizer(pol, known);
  const masked = anon.apply(clear);
  return { masked, diff: previewDiff(clear, masked, anon, pol) };
}

const marked = (clear: string, masked: string, d: PreviewDiff) =>
  d.marks.map((m) => [clear.slice(m.c[0], m.c[1]), masked.slice(m.m[0], m.m[1])]);

describe("previewDiff — pairs from the anonymizer's own map (#2531)", () => {
  it("lines every replaced value up with its token", () => {
    const clear = "logon on WS-FIN-07 from 10.1.2.3\nuser jdoe opened Project Falcon\nnothing here";
    const { masked, diff } = run(clear);
    expect(diff.mode).toBe("text");
    const pairs = marked(clear, masked, diff);
    expect(pairs).toEqual([
      ["WS-FIN-07", "ANON_HOST_1"],
      ["10.1.2.3", "ANON_IP_1"],
      ["jdoe", "ANON_USER_1"],
      ["Project Falcon", "ANON_OTHER_1"],
    ]);
    for (const m of diff.marks) expect(diff.pairs[m.pair].token).toBe(masked.slice(m.m[0], m.m[1]));
    expect(diff.counts).toEqual({ HOST: 1, IP: 1, USER: 1, OTHER: 1 });
    expect(diff.changedLines).toBe(2);
  });

  it("the same value in another case is the same pair", () => {
    const clear = "WS-FIN-07 then ws-fin-07";
    const { masked, diff } = run(clear);
    expect(marked(clear, masked, diff)).toEqual([
      ["WS-FIN-07", "ANON_HOST_1"],
      ["ws-fin-07", "ANON_HOST_1"],
    ]);
    expect(diff.marks[0].pair).toBe(diff.marks[1].pair);
    expect(diff.pairs).toHaveLength(1);
  });

  it("an account split into two tokens keeps its separator plain", () => {
    const clear = "CORP\\jdoe logged on";
    const { masked, diff } = run(clear);
    expect(masked).toMatch(/^ANON_DOMAIN_1\\ANON_USER_1 logged on$/);
    expect(marked(clear, masked, diff).map((p) => p[0])).toEqual(["CORP", "jdoe"]);
  });

  it("only tokens that occur in the masked text are returned (a shared masker minted more)", () => {
    const anon = createAnonymizer(policy(), KNOWN);
    anon.apply("other row on 10.9.9.9");
    const clear = "row on WS-FIN-07";
    const masked = anon.apply(clear);
    const diff = previewDiff(clear, masked, anon, policy());
    expect(diff.pairs.map((p) => p.value)).toEqual(["WS-FIN-07"]);
  });

  it("matches a value in its JSON-escaped form (the decision-model state panes)", () => {
    const known = { ...KNOWN, custom: [{ value: "C:\\Secret\\plan.docx", category: "OTHER" as const }] };
    const anon = createAnonymizer(policy(), known);
    const clearObj = { row: "opened C:\\Secret\\plan.docx" };
    const clear = JSON.stringify(clearObj, null, 2);
    const masked = JSON.stringify({ row: anon.apply(clearObj.row) }, null, 2);
    const diff = previewDiff(clear, masked, anon, policy());
    expect(diff.mode).toBe("text");
    expect(marked(clear, masked, diff)[0][0]).toBe("C:\\\\Secret\\\\plan.docx");
  });

  it("a one-way secret is marked to the next unchanged text, with no pair, also across lines", () => {
    const key = FAKE_RSA_KEY;
    const clear = `before\n${key}\nafter WS-FIN-07`;
    const { masked, diff } = run(clear);
    expect(masked).toContain(SECRET_PLACEHOLDER);
    expect(diff.mode).toBe("text");
    const secret = diff.marks.find((m) => m.pair === -1)!;
    expect(clear.slice(secret.c[0], secret.c[1])).toBe(key);
    expect(diff.counts.SECRET).toBe(1);
  });

  it("a newline inside a private key is not taken for the newline after it", () => {
    const key = FAKE_RSA_KEY;
    const clear = `top\n${key}\nWS-FIN-07`;
    const { masked, diff } = run(clear);
    expect(diff.mode).toBe("text");
    expect(marked(clear, masked, diff)).toEqual([
      [key, SECRET_PLACEHOLDER],
      ["WS-FIN-07", "ANON_HOST_1"],
    ]);
  });

  it("two secrets in a row are never split by guesswork (a key followed by an access key id)", () => {
    const key = FAKE_RSA_KEY;
    const clear = `top\n${key}\nAKIAIOSFODNN7EXAMPLE\nWS-FIN-07`;
    const { masked, diff } = run(clear);
    expect(masked.split("[REDACTED_SECRET]")).toHaveLength(3);
    expect(diff.mode).toBe("none");
    expect(diff.marks).toEqual([]);
  });

  it("CRLF and a trailing newline survive the walk", () => {
    const clear = "a WS-FIN-07\r\nb jdoe\r\n";
    const { diff } = run(clear);
    expect(diff.mode).toBe("text");
    expect(diff.marks).toHaveLength(2);
  });

  it("a token whose value is not at the cursor is never guessed: per-line mode marks the line unaligned", () => {
    const anon = createAnonymizer(policy(), KNOWN);
    const clearLines = ["host WS-FIN-07 ok", "row WS-FIN-07 then more text here"];
    // The second masked line was cut after masking (like a Jev row cap) — not a pure substitution.
    const maskedLines = [anon.apply(clearLines[0]), anon.apply(clearLines[1]).slice(0, 12)];
    const diff = previewDiff(clearLines.join("\n"), maskedLines.join("\n"), anon, policy());
    expect(diff.mode).toBe("lines");
    expect(diff.unalignedLines).toEqual([1]);
    expect(diff.marks).toHaveLength(1);
    expect(diff.changedLines).toBe(2);
  });

  it("a token cut in half at a row limit leaves that line unaligned, not mis-marked", () => {
    const anon = createAnonymizer(policy(), KNOWN);
    const clear = "a\nrow on WS-FIN-07";
    const masked = `a\n${anon.apply("row on WS-FIN-07").slice(0, 13)}`; // "row on ANON_H"
    const diff = previewDiff(clear, masked, anon, policy());
    expect(diff.mode).toBe("lines");
    expect(diff.unalignedLines).toEqual([1]);
    expect(diff.marks).toEqual([]);
  });

  it("different line counts that cannot be walked → mode none (the dialog falls back)", () => {
    const anon = createAnonymizer(policy(), KNOWN);
    const diff = previewDiff("one\ntwo\nthree", "something else", anon, policy());
    expect(diff.mode).toBe("none");
    expect(diff.marks).toEqual([]);
  });

  it("literal ANON_ text and a literal placeholder already in the clear text are not replacements", () => {
    const clear = `note ANON_HOST_9 and ${SECRET_PLACEHOLDER} on WS-FIN-07`;
    const { masked, diff } = run(clear);
    expect(diff.mode).toBe("text");
    expect(marked(clear, masked, diff)).toEqual([["WS-FIN-07", "ANON_HOST_1"]]);
  });

  it("a literal equal to the first host token is not marked and is not reused (#2569)", () => {
    const clear = "ANON_HOST_1 WS-FIN-07";
    const { masked, diff } = run(clear);
    expect(masked).toBe("ANON_HOST_1 ANON_HOST_2");
    expect(marked(clear, masked, diff)).toEqual([["WS-FIN-07", "ANON_HOST_2"]]);
  });
});

describe("previewDiff — possible leaks are guesses on the masked side (#2531)", () => {
  const kinds = (masked: string, d: PreviewDiff) =>
    d.warnings.map((w) => [masked.slice(w.m[0], w.m[1]), w.looksLike]);

  it("flags unreplaced IP, IPv6, email, domain and host-looking text", () => {
    const pol = policy(true, { IP: false, EMAIL: false, HOST: false, DOMAIN: false });
    const clear = "10.0.0.5 fe80::1:2 a.b@corp.example acme-intra.com SRV-SQL-02";
    const { masked, diff } = run(clear, pol, { hosts: [], accounts: [], internalDomains: [] });
    expect(kinds(masked, diff)).toEqual([
      ["10.0.0.5", "ip"],
      ["fe80::1:2", "ip"],
      ["a.b@corp.example", "email"],
      ["acme-intra.com", "domain"],
      ["SRV-SQL-02", "host"],
    ]);
  });

  it("leaves alone file names, versions, CVE ids, loopback and public IPs the policy keeps visible", () => {
    const pol = policy(false, { IP: false });
    const clear =
      "cmd.exe kernel32.dll run.ps1 v1.2.3 CVE-2021-44228 SHA-256 127.0.0.1 8.8.8.8 System.Management.Automation";
    const { diff } = run(clear, pol, { hosts: [], accounts: [], internalDomains: [] });
    expect(diff.warnings).toEqual([]);
  });

  it("never flags inside a token", () => {
    const clear = "WS-FIN-07.corp.example and jdoe@corp.example";
    const { masked, diff } = run(clear);
    for (const w of diff.warnings) expect(masked.slice(w.m[0], w.m[1])).not.toMatch(/ANON_/);
  });

  it("warnings survive the fallback", () => {
    const anon = createAnonymizer(policy(true, { IP: false }), KNOWN);
    const diff = previewDiff("x\ny\nz", "talk to 10.0.0.9", anon, policy(true, { IP: false }));
    expect(diff.mode).toBe("none");
    expect(diff.warnings.map((w) => w.looksLike)).toEqual(["ip"]);
  });
});

describe("previewDiff — large prompts stay linear (#2531)", () => {
  it("scales linearly with the prompt", () => {
    const pol = policy();
    const anon = createAnonymizer(pol, KNOWN);
    const line = "2026-01-01T00:00:00Z logon WS-FIN-07 from 10.1.2.3 by jdoe — Project Falcon file opened\n";
    const cache = new Map<number, [string, string]>();
    const texts = (n: number): [string, string] => {
      if (!cache.has(n)) {
        const clear = line.repeat(n);
        cache.set(n, [clear, anon.apply(clear)]);
      }
      return cache.get(n)!;
    };
    expectLinearScan(
      "previewDiff",
      (n) => {
        const [clear, masked] = texts(n);
        return previewDiff(clear, masked, anon, pol);
      },
      400,
    );
    const [clear, masked] = texts(4000); // ~350 KB
    expect(previewDiff(clear, masked, anon, pol).marks).toHaveLength(16000);
  });
});
