import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3014: a profile name that is very short or digits only (a C:\Users\ folder named "5") was saved as
// a USER discovery. Saved discoveries come back as custom values on a later call, and "5" then
// matched inside a SID (S-1-5-21-…) or an address and cut it apart. Such a name is still masked in
// place, but it is never learned or saved. Paths are assembled at runtime (like previewDiff.test.ts).
const BS = String.fromCharCode(0x5c);
const WIN = ["C:", "Users", ""].join(BS);
const HOME = ["", "home", ""].join("/");
const U1 = ["ANON", "USER", "1"].join("_");

function policy(maskPublicIps: boolean): AnonPolicy {
  const on = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true };
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps,
    categories: { ...on, CMD: true, REG: true, CARD: true, PHONE: true, NATID: true },
  };
}
const known = (extra: Partial<KnownEntities> = {}): KnownEntities => ({
  hosts: [],
  accounts: [],
  internalDomains: [],
  ...extra,
});
const LATER = ["S-1-5-21-5-12-7-1005 x", "seen 10.5.12.7 and fd00::5 here", "pid 12 port 007 ab"];

describe.each([true, false])("a short or digit-only profile name, maskPublicIps=%s (#3014)", (mask) => {
  it.each(["5", "12", "007", "ab"])("masks %s in place but never saves it", (name) => {
    const a = createAnonymizer(policy(mask), known());
    const out = a.apply(`${WIN}${name}${BS}AppData x`);
    expect(out).toBe(`${WIN}${U1}${BS}AppData x`);
    expect(a.restore(out)).toBe(`${WIN}${name}${BS}AppData x`);
    expect(a.discoveries()).toEqual([]);
  });

  it.each(LATER)("a saved short name never cuts %s on a later call", (later) => {
    const first = createAnonymizer(policy(mask), known());
    for (const name of ["5", "12", "007", "ab"]) first.apply(`${WIN}${name}${BS}x ${HOME}${name}/y`);
    const seeded = createAnonymizer(policy(mask), known({ custom: first.discoveries() }));
    expect(seeded.apply(later)).toBe(createAnonymizer(policy(mask), known()).apply(later));
  });

  it("still saves an ordinary profile name", () => {
    const a = createAnonymizer(policy(mask), known());
    a.apply(`${WIN}bob${BS}x ${HOME}j5/y`);
    expect(a.discoveries().map((d) => d.value)).toEqual(["bob"]);
  });
});
