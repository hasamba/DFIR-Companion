import { redactSecretText, VENDOR_SECRETS } from "./anonSecrets.js";

// #3003: a secret glued into a name ("C:\Users\bob<key>", "/home/<key>x") can be missed by the
// edge-guarded vendor shapes, and the later passes then minted the whole name as a reversible USER
// token: restore() handed the secret back and the OCR path saved it as a discovery. Inside a name the
// vendor shapes are tested with no edge guard: every "\b" and every negative look-around that is one
// character class (with an optional count) is removed. Positive look-arounds stay (mixed case, the
// "eyJ" header, the Twilio label), so the shapes keep what tells a key from a hash or a word. Derived
// from VENDOR_SECRETS, so a later edge change there follows here.
const EDGE_GUARD = /\\b|\(\?<?!\[[^\]]*\](?:\{\d+(?:,\d*)?\})?\)/g;

/** The vendor shapes with their edge guards removed; exported for the tests. */
export const GLUED_VENDOR_SECRETS: readonly RegExp[] = VENDOR_SECRETS.map(
  (re) => new RegExp(re.source.replace(EDGE_GUARD, ""), re.flags.replace("g", "")),
);
const SENTINELS = /[\uE000\uE001]/; // an address set aside or a secret already redacted

/** True when the name holds a vendor secret glued to other text, or a secret key=value. */
export function holdsGluedSecret(name: string): boolean {
  return name.split(SENTINELS).some((part) => {
    const n = ` ${part}`; // a key=value straight after a path separator reads as its own word
    return GLUED_VENDOR_SECRETS.some((re) => re.test(n)) || redactSecretText(n) !== n;
  });
}

/**
 * The anonymizer's one-way check for a value it is about to mint: `false` always when secrets are
 * not redacted. A value found to hold a secret is remembered in lower case, because the bare-name
 * pass matches in any case while the vendor shapes are case-sensitive. A value found clean is NOT
 * remembered in lower case: that would hide the secret-case spelling seen later.
 */
export function createOneWayCheck(enabled: boolean): (value: string) => boolean {
  const claimed = new Set<string>();
  return (value) => {
    if (!enabled) return false;
    const k = value.toLowerCase();
    if (claimed.has(k)) return true;
    if (!holdsGluedSecret(value)) return false;
    claimed.add(k);
    return true;
  };
}
