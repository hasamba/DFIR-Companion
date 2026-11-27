import { describe, expect, it } from "vitest";
import {
  createAnonymizer,
  type AnonPair,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";
import { sanitizeAnonMap } from "../../src/analysis/anonMap.js";

// #2996: base64 is case-sensitive, so two encoded commands that differ only in letter case are two
// payloads. They get two CMD tokens and each restores to its own text. Every other category keeps
// sharing one token across case variants (one entity, one token).

const POLICY: AnonPolicy = {
  enabled: true,
  redactSecrets: false,
  maskPublicIps: true,
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
  },
};
const KNOWN: KnownEntities = { hosts: ["ws-alpha-01"], accounts: [], internalDomains: [] };
// Synthetic blobs, built at runtime: the second differs from the first only in letter case.
const BLOB_A = ["SQBFAFgAIABo", "AGkAdABlAHMAdAA="].join("");
const BLOB_B = BLOB_A.slice(0, 4) + BLOB_A.slice(4, 12).toLowerCase() + BLOB_A.slice(12);

describe("encoded-command case keying (#2996)", () => {
  it("the two blobs really differ only in case", () => {
    expect(BLOB_B).not.toBe(BLOB_A);
    expect(BLOB_B.toLowerCase()).toBe(BLOB_A.toLowerCase());
  });

  it("gives -enc blobs that differ only by case separate tokens that each round-trip", () => {
    const a = createAnonymizer(POLICY, KNOWN);
    const input = `powershell -enc ${BLOB_A} then powershell -enc ${BLOB_B}`;
    const out = a.apply(input);
    expect(out).not.toContain(BLOB_A);
    expect(out).not.toContain(BLOB_B);
    const cmd = out.match(/ANON_CMD_\d+/g) ?? [];
    expect(new Set(cmd).size).toBe(2);
    expect(a.restore(out)).toBe(input);
  });

  it("gives FromBase64String blobs that differ only by case separate tokens", () => {
    const a = createAnonymizer(POLICY, KNOWN);
    const input = `[Convert]::FromBase64String('${BLOB_A}') and [Convert]::FromBase64String('${BLOB_B}')`;
    const out = a.apply(input);
    expect(out).not.toContain(BLOB_A);
    expect(out).not.toContain(BLOB_B);
    expect(new Set(out.match(/ANON_CMD_\d+/g) ?? []).size).toBe(2);
    expect(a.restore(out)).toBe(input);
  });

  it("still shares one token for the same blob seen twice", () => {
    const a = createAnonymizer(POLICY, KNOWN);
    const out = a.apply(`-enc ${BLOB_A} and -enc ${BLOB_A}`);
    expect(new Set(out.match(/ANON_CMD_\d+/g) ?? []).size).toBe(1);
  });

  it("keys a seeded or saved-map CMD pair exactly, and still masks the case variant", () => {
    const first = createAnonymizer(POLICY, KNOWN);
    first.apply(`-enc ${BLOB_A}`);
    const pairs: AnonPair[] = first.pairs();
    for (const mk of [
      () => createAnonymizer(POLICY, KNOWN, pairs),
      () => createAnonymizer(POLICY, KNOWN, [], pairs),
    ]) {
      const b = mk();
      const input = `-enc ${BLOB_B} vs -enc ${BLOB_A}`;
      const out = b.apply(input);
      expect(out).not.toContain(BLOB_B);
      expect(out).not.toContain(BLOB_A);
      const toks = out.match(/ANON_CMD_\d+/g) ?? [];
      expect(toks).toHaveLength(2);
      expect(toks[0]).not.toBe(toks[1]);
      expect(toks[1]).toBe(pairs.find((p) => p.category === "CMD")?.token);
      expect(b.restore(out)).toBe(input);
    }
  });

  it("lists both case variants as separate CMD discoveries", () => {
    const a = createAnonymizer(POLICY, KNOWN);
    a.apply(`-enc ${BLOB_A} -enc ${BLOB_B}`);
    const cmds = a
      .discoveries()
      .filter((d) => d.category === "CMD")
      .map((d) => d.value);
    expect(cmds).toHaveLength(2);
  });

  it("masks both case variants when CMD discoveries return as custom entities with CMD off", () => {
    const a = createAnonymizer(POLICY, KNOWN);
    a.apply(`-enc ${BLOB_A}`);
    const custom = a.discoveries().filter((d) => d.category === "CMD");
    const off: AnonPolicy = { ...POLICY, categories: { ...POLICY.categories, CMD: false } };
    const b = createAnonymizer(off, { ...KNOWN, custom });
    const input = `-enc ${BLOB_A} -enc ${BLOB_B}`;
    const out = b.apply(input);
    expect(out).not.toContain(BLOB_A);
    expect(out).not.toContain(BLOB_B);
    expect(b.restore(out)).toBe(input);
  });

  it("keeps both case variants of a CMD value in the saved map, but folds other categories", () => {
    const kept = sanitizeAnonMap({
      pairs: [
        { token: "ANON_CMD_1", value: BLOB_A, category: "CMD" },
        { token: "ANON_CMD_2", value: BLOB_B, category: "CMD" },
        { token: "ANON_HOST_1", value: "ws-alpha-01", category: "HOST" },
        { token: "ANON_HOST_2", value: "WS-ALPHA-01", category: "HOST" },
      ],
    });
    expect(kept.map((p) => p.token)).toEqual(["ANON_CMD_1", "ANON_CMD_2", "ANON_HOST_1"]);
  });

  it("still shares one token across case variants for hosts and emails", () => {
    const a = createAnonymizer(POLICY, KNOWN);
    const out = a.apply("ws-alpha-01 WS-ALPHA-01");
    expect(new Set(out.match(/ANON_HOST_\d+/g) ?? []).size).toBe(1);
    const user = ["jdoe", "ext.example"].join("@");
    const emailOnly: AnonPolicy = {
      ...POLICY,
      categories: { ...POLICY.categories, USER: false, DOMAIN: false },
    };
    const e = createAnonymizer(emailOnly, KNOWN);
    const out2 = e.apply(`${user} ${user.toUpperCase()}`);
    expect(new Set(out2.match(/ANON_EMAIL_\d+/g) ?? []).size).toBe(1);
  });
});
