import { describe, expect, it } from "vitest";
import {
  createAnonymizer,
  type AnonPair,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// #3001: a token-shaped literal whose number is already in use is escaped on the way out (#2569, #2657).
// restore() undoes exactly the escapes this anonymizer made, so the literal comes back as itself. It
// never undoes an "ANON-LITERAL_" spelling that was already in the input, nor an ambiguous one, and the
// literal is never turned into the real value. Synthetic values only.

const POLICY: AnonPolicy = {
  enabled: true,
  redactSecrets: true,
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
const HOST = ["ws-qa", "-07"].join("");
const AT = "@" + ["example", "test"].join(".");
const known = (): KnownEntities => ({ hosts: [HOST], accounts: [], internalDomains: [] });
const make = (seed: AnonPair[] = [], identity: AnonPair[] = []) =>
  createAnonymizer(POLICY, known(), seed, identity);

/** apply() each text in order, then restore each output; returns [sent, restored]. */
function roundTrip(a: ReturnType<typeof make>, texts: string[]): [string[], string[]] {
  const sent = texts.map((t) => a.apply(t));
  return [sent, sent.map((s) => a.restore(s))];
}

describe("restore() undoes this anonymizer's own literal escapes (#3001)", () => {
  it("a literal equal to a token minted by an earlier call restores as itself", () => {
    const [sent, back] = roundTrip(make(), [`logon ${HOST}`, "cmd ANON_HOST_1 ran"]);
    // The text that goes out is unchanged by the fix (byte for byte).
    expect(sent).toEqual(["logon ANON_HOST_1", "cmd ANON-LITERAL_HOST_1 ran"]);
    expect(back).toEqual([`logon ${HOST}`, "cmd ANON_HOST_1 ran"]);
  });

  it("a literal equal to a Watson seed token, swallowed into an email value, restores as itself", () => {
    const seed: AnonPair[] = [
      { token: ["ANON", "OTHER", "1"].join("_"), value: "Wv9first", category: "OTHER" },
    ];
    const input = `x ANON_OTHER_1${AT}`;
    const [sent, back] = roundTrip(make(seed), [input]);
    expect(sent).toEqual(["x ANON_EMAIL_1"]);
    expect(back).toEqual([input]);
    expect(back[0]).not.toContain("Wv9first");
  });

  it("a literal equal to a saved token restores as itself", () => {
    const identity: AnonPair[] = [
      { token: ["ANON", "HOST", "7"].join("_"), value: "fs-09", category: "HOST" },
    ];
    const input = `ANON_HOST_7 attacked ${HOST}`;
    const [sent, back] = roundTrip(make([], identity), [input]);
    expect(sent).toEqual(["ANON-LITERAL_HOST_7 attacked ANON_HOST_8"]);
    expect(back).toEqual([input]);
  });

  it("keeps the literal's exact case", () => {
    const [sent, back] = roundTrip(make(), [`logon ${HOST}`, "then anon_host_1 seen"]);
    expect(sent[1]).toBe("then ANON-LITERAL_host_1 seen");
    expect(back[1]).toBe("then anon_host_1 seen");
  });

  it("a literal followed by a digit restores as itself", () => {
    const input = "id ANON_HOST_12 and ANON_HOST_1 9";
    const [sent, back] = roundTrip(make(), [`logon ${HOST}`, input]);
    expect(sent[1]).toBe("id ANON_HOST_12 and ANON-LITERAL_HOST_1 9");
    expect(back[1]).toBe(input);
  });

  it("the escaped spelling in the model's answer restores as the literal, never as the real host", () => {
    const a = make();
    a.apply(`logon ${HOST}`);
    a.apply("cmd ANON_HOST_1");
    expect(a.restore("Planted ANON-LITERAL_HOST_1 differs from ANON_HOST_1")).toBe(
      `Planted ANON_HOST_1 differs from ${HOST}`,
    );
  });

  it("an escaped spelling this anonymizer never produced stays as it is", () => {
    const a = make();
    a.apply(`logon ${HOST}`);
    expect(a.restore("odd ANON-LITERAL_HOST_1")).toBe("odd ANON-LITERAL_HOST_1");
  });

  it("never undoes an ANON-LITERAL_ spelling that was already in the input", () => {
    const [sent, back] = roundTrip(make(), [`logon ${HOST}`, "a ANON-LITERAL_HOST_1 b ANON_HOST_1"]);
    expect(sent[1]).toBe("a ANON-LITERAL_HOST_1 b ANON-LITERAL_HOST_1");
    expect(back[1]).toBe(sent[1]);
    expect(back[1]).not.toContain(HOST);
  });

  it("leaves an ambiguous escape marked: two spellings that escape to one", () => {
    const [sent, back] = roundTrip(make(), [`logon ${HOST}`, "anon_host_1 and ANON_host_1"]);
    expect(sent[1]).toBe("ANON-LITERAL_host_1 and ANON-LITERAL_host_1");
    expect(back[1]).toBe(sent[1]);
  });

  it("leaves a raw ANON-LITERAL_ value marked when an escape joins it (not injective)", () => {
    const input = `ANON_HOST_1${AT} then ANON-LITERAL_HOST_1${AT}`;
    const [, back] = roundTrip(make(), [`logon ${HOST}`, input]);
    expect(back[1]).toBe(`ANON-LITERAL_HOST_1${AT} then ANON-LITERAL_HOST_1${AT}`);
    expect(back[1]).not.toContain(HOST);
  });

  it("restoreDeep undoes the escape in keys and leaves alike", () => {
    const a = make();
    a.apply(`logon ${HOST}`);
    a.apply("cmd ANON_HOST_1");
    expect(a.restoreDeep({ "ANON-LITERAL_HOST_1": ["ANON-LITERAL_HOST_1 on ANON_HOST_1"] })).toEqual({
      "ANON-LITERAL_HOST_1": [`ANON_HOST_1 on ${HOST}`],
    });
  });

  it("restore once: a second restore of restored text would read the literal as the token", () => {
    // The documented contract (anonymize.ts restore()): its output is never fed back to restore().
    // Both callers restore once (providerCall.ts, converseRestored.ts — see their tests).
    const a = make();
    a.apply(`logon ${HOST}`);
    const once = a.restore(a.apply("cmd ANON_HOST_1"));
    expect(once).toBe("cmd ANON_HOST_1");
    expect(a.restore(once)).toBe(`cmd ${HOST}`);
  });

  it("without any escape, restore() is unchanged", () => {
    const a = make();
    const sent = a.apply(`ANON_HOST_1 on ${HOST}`);
    expect(sent).toBe("ANON_HOST_1 on ANON_HOST_2");
    expect(a.restore(sent)).toBe(`ANON_HOST_1 on ${HOST}`);
  });
});
