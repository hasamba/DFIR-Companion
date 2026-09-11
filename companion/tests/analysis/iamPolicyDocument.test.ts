// The policy-document reader (#931 item 6): a CloudTrail document is read for its OWN words —
// which operators, which effects, which principals — and digested raw before any decode, so two
// unreadable documents stay two rows. Nothing about effective access is inferred.
import { describe, expect, it } from "vitest";
import {
  actionMatches,
  ESCALATION_PRIMITIVES,
  readPolicyDocument,
  type PolicyReading,
} from "../../src/analysis/iamPolicyDocument.js";

const doc = (statements: unknown): string => JSON.stringify({ Version: "2012-10-17", Statement: statements });
const readable = (raw: unknown): PolicyReading => {
  const r = readPolicyDocument(raw);
  if (!r.readable) throw new Error(`unreadable: ${r.reason}`);
  return r;
};

describe("readPolicyDocument — decoding", () => {
  it("reads CloudTrail's escaped-JSON string shape first", () => {
    const r = readable(doc([{ Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::b/*" }]));
    expect(r.statements).toHaveLength(1);
    expect(r.statements[0].actions).toEqual({ op: "Action", values: ["s3:GetObject"] });
    expect(r.effect).toBe("grants");
  });
  it("falls back to percent-decoding only when the text is demonstrably encoded", () => {
    const encoded = encodeURIComponent(doc([{ Effect: "Allow", Action: "*", Resource: "*" }]));
    expect(encoded.startsWith("%7B")).toBe(true);
    const r = readable(encoded);
    expect(r.reading).toContain("all actions on all resources");
  });
  it("keeps a literal percent sign inside a JSON string readable (JSON first, never decode first)", () => {
    const r = readable(
      doc([{ Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::b/100%25/*" }]),
    );
    expect(r.statements[0].resources.values[0]).toBe("arn:aws:s3:::b/100%25/*");
  });
  it("a lone percent in an encoded document is unreadable with the reason, and still digested", () => {
    const r = readPolicyDocument("%7B%22Version%22%3A%2");
    expect(r.readable).toBe(false);
    if (!r.readable) expect(r.reason).toMatch(/percent/);
    expect(r.rawDigest).toMatch(/^[0-9a-f]{16}$/);
  });
  it("two different unreadable documents have two raw digests", () => {
    const a = readPolicyDocument("not json at all");
    const b = readPolicyDocument("not json either");
    expect(a.rawDigest).not.toBe(b.rawDigest);
  });
  it("over 64 KiB, a non-object, and a document without Statement are unreadable", () => {
    expect(readPolicyDocument(`"${"x".repeat(70000)}"`).readable).toBe(false);
    expect(readPolicyDocument("[1,2]").readable).toBe(false);
    expect(readPolicyDocument('{"Version":"2012-10-17"}').readable).toBe(false);
    expect(readPolicyDocument(null).readable).toBe(false);
    expect(readPolicyDocument(42).readable).toBe(false);
  });
  it("accepts an already-parsed object (an exporter may have parsed the string)", () => {
    const r = readable({ Statement: { Effect: "Deny", Action: "*", Resource: "*" } });
    expect(r.effect).toBe("denies");
  });
  it("normalises scalar-or-array on Statement, Action, NotAction, Resource, NotResource", () => {
    const r = readable(
      doc({ Effect: "Allow", NotAction: "iam:*", NotResource: ["arn:aws:s3:::x", "arn:aws:s3:::y"] }),
    );
    expect(r.statements[0].actions).toEqual({ op: "NotAction", values: ["iam:*"] });
    expect(r.statements[0].resources).toEqual({
      op: "NotResource",
      values: ["arn:aws:s3:::x", "arn:aws:s3:::y"],
    });
  });
});

describe("readPolicyDocument — the reading", () => {
  it("names the four broad forms and marks each broad", () => {
    const forms: Array<[unknown, string]> = [
      [{ Effect: "Allow", Action: "*", Resource: "*" }, "all actions on all resources"],
      [{ Effect: "Allow", NotAction: "iam:*", Resource: "*" }, "all actions except iam:* on all resources"],
      [
        { Effect: "Allow", Action: "*", NotResource: "arn:aws:s3:::x" },
        "all actions on all resources except arn:aws:s3:::x",
      ],
      [
        { Effect: "Allow", NotAction: ["iam:*", "sts:*"], NotResource: "arn:aws:s3:::x" },
        "all actions except iam:*, sts:* on all resources except arn:aws:s3:::x",
      ],
    ];
    for (const [st, words] of forms) {
      const r = readable(doc([st]));
      expect(r.reading).toContain(words);
      expect(r.broad).toBe(true);
    }
  });
  it("names all-<service> actions", () => {
    const r = readable(doc([{ Effect: "Allow", Action: "s3:*", Resource: "arn:aws:s3:::b" }]));
    expect(r.reading).toContain("all s3 actions");
  });
  it("names escalation primitives matched through AWS globs — *, ?, case-insensitive", () => {
    const r = readable(
      doc([
        { Effect: "Allow", Action: ["IAM:passrole", "iam:Put?olePolicy", "lambda:Create*"], Resource: "*" },
      ]),
    );
    expect(r.primitives).toEqual(
      expect.arrayContaining(["iam:PassRole", "iam:PutRolePolicy", "lambda:CreateFunction"]),
    );
    expect(r.reading).toContain("iam:PassRole");
    expect(r.broad).toBe(true);
  });
  it("never reports a NotAction value as granted", () => {
    const r = readable(doc([{ Effect: "Allow", NotAction: "iam:PassRole", Resource: "arn:aws:s3:::b" }]));
    expect(r.primitives).toEqual([]);
    expect(r.reading).not.toMatch(/grants iam:PassRole/);
    expect(r.reading).toContain("except iam:PassRole");
  });
  it("a narrow grant is neither broad nor a primitive, and is summarised by count", () => {
    const r = readable(
      doc([
        {
          Effect: "Allow",
          Action: ["s3:GetObject", "s3:ListBucket"],
          Resource: ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
        },
      ]),
    );
    expect(r.broad).toBe(false);
    expect(r.primitives).toEqual([]);
    expect(r.reading).toContain("2 actions on 2 resources");
  });
  it("Deny-only is 'denies', mixed is 'mixed', and Deny statements are counted", () => {
    const d = readable(doc([{ Effect: "Deny", Action: "*", Resource: "*" }]));
    expect(d.effect).toBe("denies");
    expect(d.reading).toContain("denies 1 statement");
    expect(d.broad).toBe(false);
    const m = readable(
      doc([
        { Effect: "Deny", Action: "s3:*", Resource: "*" },
        { Effect: "Allow", Action: "ec2:Describe*", Resource: "*" },
      ]),
    );
    expect(m.effect).toBe("mixed");
  });
  it("a Condition anywhere makes the reading conditional", () => {
    const r = readable(
      doc([
        {
          Effect: "Allow",
          Action: "*",
          Resource: "*",
          Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } },
        },
      ]),
    );
    expect(r.conditional).toBe(true);
    expect(readable(doc([{ Effect: "Allow", Action: "*", Resource: "*" }])).conditional).toBe(false);
  });
  it("bounds the reading to 220 characters and keeps the tail", () => {
    const actions = Array.from({ length: 60 }, (_, i) => `svc${i}:*`);
    const r = readable(
      doc([
        { Effect: "Allow", Action: actions, Resource: "*" },
        { Effect: "Deny", Action: "s3:*", Resource: "*" },
      ]),
    );
    expect(r.reading.length).toBeLessThanOrEqual(220);
    expect(r.reading).toMatch(/denies 1 statement$/);
  });
});

describe("readPolicyDocument — hostile shapes never escape", () => {
  it("a pattern of thirty thousand stars is matched linearly, not compiled — the import survives", () => {
    const stars = "*".repeat(30000);
    expect(actionMatches(stars, "iam:PassRole")).toBe(true);
    expect(actionMatches(`${stars}x`, "iam:PassRole")).toBe(false);
    const r = readable(
      doc([{ Effect: "Allow", Action: [stars, `iam:${"*?".repeat(2000)}`], Resource: "*" }]),
    );
    expect(r.broad).toBe(true);
  });
  it("a small but very deep parsed object is unreadable, not a stack overflow", () => {
    let deep: unknown = { Effect: "Allow", Action: "*", Resource: "*" };
    for (let i = 0; i < 5000; i++) deep = { x: deep };
    const r = readPolicyDocument({ Statement: [deep] });
    expect(r.readable).toBe(false);
    if (!r.readable) expect(r.reason).toMatch(/deep/);
    const wide = {
      Statement: Array.from({ length: 30000 }, () => ({
        Effect: "Allow",
        Action: "s3:GetObject",
        Resource: "*",
      })),
    };
    expect(readPolicyDocument(wide).readable).toBe(false);
  });
  it("an exclusion or an all-actions grant scoped to named resources is summarised, not promoted", () => {
    const ex = readable(doc([{ Effect: "Allow", NotAction: "iam:*", Resource: "arn:aws:s3:::b" }]));
    expect(ex.broad).toBe(false);
    expect(ex.reading).toContain("all actions except iam:* on 1 resource");
    const all = readable(doc([{ Effect: "Allow", Action: "*", Resource: "arn:aws:s3:::b" }]));
    expect(all.broad).toBe(false);
    expect(all.primitives).toEqual([]);
    expect(all.reading).toContain("all actions on 1 resource");
    const svc = readable(
      doc([{ Effect: "Allow", Action: "iam:*", Resource: "arn:aws:iam::111122223333:user/bob" }]),
    );
    expect(svc.broad).toBe(true);
    expect(svc.primitives).toContain("iam:CreateAccessKey");
  });
});

describe("readPolicyDocument — digests", () => {
  it("the same document with reordered keys is one canonical digest; one character apart is two", () => {
    const a = readable(
      '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}',
    );
    const b = readable(
      '{"Statement":[{"Resource":"*","Action":"s3:*","Effect":"Allow"}],"Version":"2012-10-17"}',
    );
    const c = readable(
      '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"x"}]}',
    );
    expect(a.digest).toBe(b.digest);
    expect(a.digest).not.toBe(c.digest);
    expect(a.rawDigest).not.toBe(b.rawDigest);
  });
});

describe("actionMatches", () => {
  it("is an AWS glob: * and ? wildcards, case-insensitive, whole-string", () => {
    expect(actionMatches("*", "iam:PassRole")).toBe(true);
    expect(actionMatches("iam:*", "iam:PassRole")).toBe(true);
    expect(actionMatches("iam:Pass*", "iam:PassRole")).toBe(true);
    expect(actionMatches("iam:Put?olePolicy", "iam:PutRolePolicy")).toBe(true);
    expect(actionMatches("IAM:PASSROLE", "iam:PassRole")).toBe(true);
    expect(actionMatches("iam:PassRol", "iam:PassRole")).toBe(false);
    expect(actionMatches("s3:*", "iam:PassRole")).toBe(false);
    expect(actionMatches("iam:Pass.ole", "iam:PassRole")).toBe(false); // a dot is literal
  });
});

describe("ESCALATION_PRIMITIVES", () => {
  it("holds the documented set, each in canonical service:Action form", () => {
    for (const p of ESCALATION_PRIMITIVES) expect(p).toMatch(/^[a-z0-9-]+:[A-Za-z]+$/);
    expect(ESCALATION_PRIMITIVES).toEqual(
      expect.arrayContaining([
        "iam:PassRole",
        "sts:AssumeRole",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:DeleteUserPermissionsBoundary",
        "iam:DeleteRolePermissionsBoundary",
        "iam:DeactivateMFADevice",
        "iam:DeleteVirtualMFADevice",
      ]),
    );
  });
});
