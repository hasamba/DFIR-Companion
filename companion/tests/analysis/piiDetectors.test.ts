import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  luhnValid,
  israeliIdValid,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

const NONE: KnownEntities = { hosts: [], accounts: [], internalDomains: [] };

function policy(over: Partial<AnonPolicy["categories"]> = {}): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps: false,
    categories: {
      IP: false,
      EMAIL: false,
      USER: false,
      HOST: false,
      DOMAIN: false,
      PATH: false,
      CMD: false,
      REG: false,
      CARD: false,
      PHONE: false,
      NATID: false,
      ...over,
    },
  };
}

describe("CARD detector", () => {
  // Publicly documented test numbers. All Luhn-valid, none issued to anyone.
  it("tokenizes Luhn-valid card numbers with a plausible issuer prefix", () => {
    const a = createAnonymizer(policy({ CARD: true }), NONE);
    for (const card of ["4111111111111111", "5500005555555559", "378282246310005"]) {
      const out = a.apply(`charge to ${card} declined`);
      expect(out, card).not.toContain(card);
      expect(out, card).toMatch(/ANON_CARD_\d+/);
      expect(a.restore(out)).toBe(`charge to ${card} declined`);
    }
  });

  it("accepts spaced and dashed groupings (4-4-4-4)", () => {
    const a = createAnonymizer(policy({ CARD: true }), NONE);
    const out = a.apply("card 4111 1111 1111 1111 on file");
    expect(out).toBe("card ANON_CARD_1 on file");
    expect(a.restore(out)).toBe("card 4111 1111 1111 1111 on file");
  });

  it("accepts the 4-6-5 Amex grouping", () => {
    const a = createAnonymizer(policy({ CARD: true }), NONE);
    const out = a.apply("card 3782 822463 10005 on file");
    expect(out).toBe("card ANON_CARD_1 on file");
    expect(a.restore(out)).toBe("card 3782 822463 10005 on file");
  });

  // Regression test: an earlier version of CARD_RE allowed a separator between EVERY digit
  // (not just at real group boundaries), so two unrelated bare numbers sitting next to each
  // other — a 5-digit field and an 8-digit field, joined by one space — got concatenated into
  // a single 13-digit candidate that happened to pass both the issuer-prefix and Luhn filters.
  // "30001 35174909" -> stripped "3000135174909" -> starts with 3, Luhn-valid -> was wrongly
  // masked. Neither "30001" (5 digits) nor "35174909" (8 digits) is itself a valid card length,
  // and the space between them is not a real 4-4-4-4 / 4-6-5 / 4-4-4-4-3 boundary, so the
  // tightened regex must not match across it at all.
  it("does NOT merge two unrelated adjacent bare numbers into a card candidate", () => {
    const a = createAnonymizer(policy({ CARD: true }), NONE);
    const out = a.apply("field 30001 35174909 recorded");
    expect(out).toBe("field 30001 35174909 recorded");
  });

  it("rejects Luhn-invalid numbers", () => {
    const a = createAnonymizer(policy({ CARD: true }), NONE);
    const out = a.apply("value 4111111111111112 here");
    expect(out).toBe("value 4111111111111112 here");
  });

  // Self-proving: 1234567890123452 is Luhn-VALID (verified below) but starts with "1", which is
  // not a card issuer prefix. The digit run used in an earlier version of this test
  // ("1234567890123456") is Luhn-INVALID on its own, so it was already rejected by the Luhn
  // filter alone — deleting the prefix guard entirely would not have failed that test. This one
  // isolates the prefix filter: only it can be responsible for rejecting a number Luhn would
  // have accepted.
  it("rejects a Luhn-VALID number whose issuer prefix is not a card prefix", () => {
    const notACard = "1234567890123452";
    expect(luhnValid(notACard)).toBe(true); // proves Luhn would have passed it
    const a = createAnonymizer(policy({ CARD: true }), NONE);
    expect(a.apply(`offset ${notACard} bytes`)).toBe(`offset ${notACard} bytes`); // only the prefix filter can be rejecting it
  });

  it("does nothing when the category is off", () => {
    const a = createAnonymizer(policy(), NONE);
    expect(a.apply("charge to 4111111111111111")).toBe("charge to 4111111111111111");
  });
});

describe("PHONE detector", () => {
  it("tokenizes E.164 numbers", () => {
    const a = createAnonymizer(policy({ PHONE: true }), NONE);
    const out = a.apply("called +972501234567 twice");
    expect(out).not.toContain("+972501234567");
    expect(out).toMatch(/ANON_PHONE_1/);
    expect(a.restore(out)).toBe("called +972501234567 twice");
  });

  it("tokenizes Israeli mobile and landline numbers, dashed or bare", () => {
    for (const phone of ["052-1234567", "0521234567", "03-1234567"]) {
      const a = createAnonymizer(policy({ PHONE: true }), NONE);
      const out = a.apply(`contact ${phone} now`);
      expect(out, phone).not.toContain(phone);
      expect(out, phone).toMatch(/ANON_PHONE_1/);
      expect(a.restore(out)).toBe(`contact ${phone} now`);
    }
  });

  it("tokenizes NANP numbers only when separators are present", () => {
    const a = createAnonymizer(policy({ PHONE: true }), NONE);
    const out = a.apply("dial 555-123-4567 please");
    expect(out).not.toContain("555-123-4567");
    expect(out).toMatch(/ANON_PHONE_1/);
  });

  it("leaves a bare ten-digit run alone", () => {
    const a = createAnonymizer(policy({ PHONE: true }), NONE);
    expect(a.apply("seq 5551234567 done")).toContain("5551234567");
  });

  it("does not fire on dotted quads or timestamps", () => {
    const a = createAnonymizer(policy({ PHONE: true }), NONE);
    expect(a.apply("host 192.168.1.1 up")).toContain("192.168.1.1");
    expect(a.apply("at 2026-07-26 12:00:00")).toContain("2026-07-26");
  });

  // Fix 1: PHONE_E164 must not fire on a "+" that continues a token rather than starting a
  // number — module+offset (crash dumps / stack traces) and SemVer build metadata both use a
  // bare "+<digits>" suffix glued directly onto a preceding identifier.
  it("does not fire on a module+offset suffix (crash-dump / stack-trace notation)", () => {
    const a = createAnonymizer(policy({ PHONE: true }), NONE);
    expect(a.apply("kernel32.dll+1245184 offset")).toBe("kernel32.dll+1245184 offset");
  });

  it("does not fire on SemVer build metadata", () => {
    const a = createAnonymizer(policy({ PHONE: true }), NONE);
    expect(a.apply("release 1.0.0+20130313144700 metadata")).toBe("release 1.0.0+20130313144700 metadata");
  });

  it("does not fire on a tool version+timestamp build tag", () => {
    const a = createAnonymizer(policy({ PHONE: true }), NONE);
    expect(a.apply("Autoruns v14.11+20260726120000 build")).toBe("Autoruns v14.11+20260726120000 build");
  });

  // Pins the boundary of the module+offset/SemVer guard above: a "+" preceded by punctuation
  // that is NOT letter/digit/dot/underscore/dash — e.g. a label colon — still starts a genuine
  // E.164 number and must still be masked.
  it("still tokenizes a + number immediately after a label colon", () => {
    const a = createAnonymizer(policy({ PHONE: true }), NONE);
    const out = a.apply("Tel:+972501234567");
    expect(out).toBe("Tel:ANON_PHONE_1");
    expect(a.restore(out)).toBe("Tel:+972501234567");
  });

  // Fix 2 (as specified): the existing "at 2026-07-26 12:00:00" case is rejected by digit-group
  // WIDTH (4-2-2 / 2-2-2, not 3-3-4) regardless of whether ":" is a valid separator. A bare
  // HH:MM:SS has that same 2-2-2 width, so it is rejected for the identical width reason — see
  // the note in the fix report on why this case, taken alone, does not yet isolate the
  // separator-class rule from the width rule.
  it("does not let the NANP separator class swallow a bare HH:MM:SS timestamp", () => {
    const a = createAnonymizer(policy({ PHONE: true }), NONE);
    expect(a.apply("at 12:00:00")).toBe("at 12:00:00");
  });

  // This is the case that actually isolates the separator-class rule: "123:456:7890" has the
  // exact 3-3-4 digit-group width NANP requires, with ":" as the separator. Confirmed by
  // deliberately widening PHONE_NANP's class to `[-. :]` in isolation — under that mutation this
  // string DOES match, while "at 12:00:00" (2-2-2 width) still does not. So this test, not the
  // HH:MM:SS one, is what would catch a future widening of the separator class to include ":".
  it("does not let the NANP separator class swallow a colon-separated 3-3-4 digit run", () => {
    const a = createAnonymizer(policy({ PHONE: true }), NONE);
    expect(a.apply("id 123:456:7890 recorded")).toBe("id 123:456:7890 recorded");
  });
});

describe("israeliIdValid", () => {
  // Structurally valid but not issued — these are check-digit exercises, not real identities.
  it("accepts check-digit-valid nine-digit numbers", () => {
    expect(israeliIdValid("123456782")).toBe(true);
    expect(israeliIdValid("000000018")).toBe(true);
  });
  it("rejects check-digit-invalid numbers", () => {
    expect(israeliIdValid("123456789")).toBe(false);
    expect(israeliIdValid("000000019")).toBe(false);
  });
});

describe("NATID detector", () => {
  it("tokenizes a check-digit-valid ID", () => {
    const a = createAnonymizer(policy({ NATID: true }), NONE);
    const out = a.apply("subject id 123456782 on file");
    expect(out).not.toContain("123456782");
    expect(out).toMatch(/ANON_NATID_1/);
    expect(a.restore(out)).toBe("subject id 123456782 on file");
  });

  it("leaves check-digit-invalid nine-digit numbers alone", () => {
    const a = createAnonymizer(policy({ NATID: true }), NONE);
    expect(a.apply("offset 123456789 bytes")).toContain("123456789");
  });

  it("does not fire inside longer digit runs or dotted numbers", () => {
    const a = createAnonymizer(policy({ NATID: true }), NONE);
    expect(a.apply("size 1234567823 bytes")).toContain("1234567823");
    expect(a.apply("build 4.123456782.9")).toContain("4.123456782.9");
  });

  // Real-world regression coverage: two actual current-epoch timestamps must stay untouched.
  // NOTE: this assertion alone does NOT prove the lookaround guard is doing the rejecting — see
  // the fix-4 report. For "1753564800" both embedded nine-digit substrings are check-digit
  // INVALID, and for "1753564800123" the one embedded valid substring (offset 3) is never reached
  // by a left-to-right non-overlapping scan because the invalid offset-0 substring is matched
  // first and consumes through offset 9. So the checksum/scan mechanics alone would already leave
  // this string untouched even with no lookaround at all. Kept as a real-world sanity check; the
  // two tests below are the ones that actually isolate the lookaround.
  it("does not fire on real-world ten-digit or thirteen-digit unix timestamps", () => {
    const a = createAnonymizer(policy({ NATID: true }), NONE);
    expect(a.apply("ts 1753564800 and 1753564800123")).toBe("ts 1753564800 and 1753564800123");
  });

  // Isolates the lookaround by construction: "123456782" (check-digit-valid, see israeliIdValid
  // tests above) sits at offset 0 of a ten-digit run. A pure digit run's first regex match is
  // always found at offset 0, so this substring IS reachable by a naive scan — unlike the
  // real-world timestamp above. Only the trailing lookahead (blocked by the extra digit at
  // index 9) keeps it from being tokenized. Verified by mutation in the fix-4 report: removing
  // the lookaround from NATID_RE turns this into "ts [TOKEN]9 recorded".
  it("does not fire on a ten-digit run whose reachable offset-0 substring is check-digit-valid", () => {
    const a = createAnonymizer(policy({ NATID: true }), NONE);
    expect(a.apply("ts 1234567829 recorded")).toBe("ts 1234567829 recorded");
  });

  // Same construction for the thirteen-digit (millisecond) case. Offset 0 is the ONLY substring
  // of a thirteen-digit run a left-to-right non-overlapping scan can ever reach (any other offset
  // falls inside the span the first match already consumed), so putting the valid ID there is the
  // only way to isolate the guard for this length at all. Verified by mutation in the fix-4
  // report: removing the lookaround turns this into "ts [TOKEN]0000 recorded".
  it("does not fire on a thirteen-digit run whose reachable offset-0 substring is check-digit-valid", () => {
    const a = createAnonymizer(policy({ NATID: true }), NONE);
    expect(a.apply("ts 1234567820000 recorded")).toBe("ts 1234567820000 recorded");
  });

  // Fix (underscore lookbehind): session/request/ticket/backup IDs are routinely glued to a
  // preceding label with an underscore in forensic text (session_id_..., txn_..., backup_...).
  // Before this fix, "_" was not excluded by NATID_RE's lookbehind, so a check-digit-valid ID
  // sitting right after one of these labels was wrongly tokenized.
  it("does not fire when a leading underscore glues it to a snake_case identifier", () => {
    const a = createAnonymizer(policy({ NATID: true }), NONE);
    expect(a.apply("session_id_123456782 recorded")).toBe("session_id_123456782 recorded");
  });

  // Symmetric fix: the trailing lookahead excludes "_" too, since the same identifier schemes
  // just as often glue a qualifier onto the TRAILING side (txn_123456782_archived).
  it("does not fire when a trailing underscore glues it to a snake_case qualifier", () => {
    const a = createAnonymizer(policy({ NATID: true }), NONE);
    expect(a.apply("id 123456782_archived recorded")).toBe("id 123456782_archived recorded");
  });

  // Pins the boundary of the underscore fix: a genuine standalone ID immediately adjacent to
  // ORDINARY punctuation (a label colon, parentheses) is still tokenized — only "_" (plus the
  // pre-existing "\d", ".", "-") blocks the match, so a future widening of the exclusion set
  // would be caught here.
  it("still tokenizes a genuine ID immediately adjacent to punctuation", () => {
    const a = createAnonymizer(policy({ NATID: true }), NONE);
    const out1 = a.apply("ID:123456782 recorded");
    expect(out1).toBe("ID:ANON_NATID_1 recorded");
    expect(a.restore(out1)).toBe("ID:123456782 recorded");

    const b = createAnonymizer(policy({ NATID: true }), NONE);
    const out2 = b.apply("subject (123456782) flagged");
    expect(out2).toBe("subject (ANON_NATID_1) flagged");
    expect(b.restore(out2)).toBe("subject (123456782) flagged");
  });
});
