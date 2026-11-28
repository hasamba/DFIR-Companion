import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3047 (part 2): the profile pass read everything after the profile folder to the line end as the user name
// and ran before the address, card and encoded-command passes, so a value later on that line was hidden
// only inside the user token. The value now gets its own token, and every other piece of the old name
// stays masked: nothing that was inside the user token goes out in clear.

const USERS = ["C:", "Users", ""].join("\\"); // a profile-path prefix, built at runtime
const KNOWN: KnownEntities = { hosts: [], accounts: [], internalDomains: [] };
const IP = [10, 0, 0, 5].join("."); // built at runtime: a synthetic private address
const CARD = ["4111", "1111", "1111", "1111"].join(" "); // a synthetic test card number
const BLOB = ["SQBFAFgAIAAo", "AE4AZQB3AC0ATwBi"].join(""); // a synthetic encoded command
function policy(mask = true): AnonPolicy {
  const on = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true, CMD: true };
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps: mask,
    categories: { ...on, REG: true, CARD: true, PHONE: true, NATID: true },
  };
}
function fresh(text: string, known: KnownEntities = KNOWN, mask = true) {
  const a = createAnonymizer(policy(mask), known);
  const out = a.apply(text);
  return { out, restored: a.restore(out), saved: a.discoveries() };
}
/** The output with its tokens removed: what goes out in clear. */
const clear = (out: string) => out.replace(/ANON_[A-Z]+_\d+/g, " ");

describe("values on the line of a profile path get their own tokens (#3047)", () => {
  it("gives an address and a card their own tokens and keeps the words between masked", () => {
    const text = `${USERS}jdoe ran from ${IP} card ${CARD} x`;
    const r = fresh(text);
    expect(r.out).toBe(`${USERS}ANON_USER_1 ANON_IP_1 ANON_USER_2 ANON_CARD_1 ANON_USER_3`);
    expect(r.restored).toBe(text);
  });

  it("gives an encoded command its own token", () => {
    const text = `${USERS}jdoe ran powershell -enc ${BLOB} x`;
    const r = fresh(text);
    expect(r.out).toMatch(/ANON_CMD_1/); // the flag stays inside the masked words, as before
    expect(r.out).not.toContain(BLOB);
    expect(clear(r.out)).not.toMatch(/jdoe|powershell|\bx\b/);
    expect(r.restored).toBe(text);
  });

  it("keeps a glued value its own pass cannot read whole masked", () => {
    for (const glued of [`${IP}12`, `1-enc ${BLOB}`, [8, 8, 8, 823456789].join(".")]) {
      const text = `${USERS}jdoe ran ${glued} x`;
      const r = fresh(text);
      expect(clear(r.out)).not.toMatch(/\d|jdoe|SQBF|ran|\bx\b/);
      expect(r.restored).toBe(text);
    }
  });

  it("keeps a public address masked with public masking off", () => {
    const pub = [8, 8, 8, 8].join(".");
    const text = `${USERS}jdoe ran ${pub} then ${IP}`;
    const r = fresh(text, KNOWN, false);
    expect(clear(r.out)).not.toMatch(/\d|jdoe|ran|then/);
    expect(r.restored).toBe(text);
  });

  it("leaves a plain or spaced profile name one token, saved as before", () => {
    expect(fresh(`${USERS}John Smith`).out).toBe(`${USERS}ANON_USER_1`);
    const r = fresh(`${USERS}jdoe ran twice`);
    expect(r.out).toBe(`${USERS}ANON_USER_1`);
    expect(r.saved).toContainEqual({ value: "jdoe ran twice", category: "USER" });
  });

  it("still saves the whole old name, so a later call and a verbatim repeat stay masked", () => {
    const line = `jdoe ran from ${IP} x`;
    const r = fresh(`${USERS}${line} and again ${line}`);
    expect(r.saved).toContainEqual({ value: `${line} and again ${line}`, category: "USER" });
    const first = fresh(`${USERS}${line}`);
    expect(first.saved).toContainEqual({ value: line, category: "USER" });
    const later = fresh(`repeat: ${line}`, { ...KNOWN, custom: first.saved });
    expect(clear(later.out)).not.toMatch(/jdoe|\bx\b|\d/);
  });

  it("saves none of the pieces between the values", () => {
    const r = fresh(`${USERS}jdoe ran from ${IP} card ${CARD} x`);
    const users = r.saved.filter((e) => e.category === "USER").map((e) => e.value);
    expect(users).toEqual([`jdoe ran from ${IP} card ${CARD} x`]);
  });
});
