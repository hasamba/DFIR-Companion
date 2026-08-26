import { describe, it, expect } from "vitest";
import { networkTokens } from "../../src/analysis/networkTokens.js";

// Extracted from velociraptorImport in #649. Asserting the scanner DIRECTLY, rather than only
// through whether two events merged, is the point of the extraction: the boundary rule was wrong
// three times (#643, #646, #649) and each round was diagnosed by asking what token a message
// produced. These pin the answer.

describe("networkTokens — addresses", () => {
  const found = (s: string): string[] => networkTokens(s.toLowerCase());

  it.each([
    ["203.0.113.1", ["203.0.113.1"]],
    ["fe80::1", ["fe80::1"]],
    ["::1", ["::1"]],
    ["1::", ["1::"]],
    ["2001:db8::1", ["2001:db8::1"]],
    ["2001:0db8:85a3:0000:0000:8a2e:0370:7334", ["2001:0db8:85a3:0000:0000:8a2e:0370:7334"]],
    ["2001:0:0:0:0:0:0:1", ["2001:0:0:0:0:0:0:1"]],
  ])("finds %s", (addr, expected) => {
    expect(found(`tgtip: ${addr} ¦ tgtport: 443`)).toEqual(expected);
  });

  it.each(["peer=%;", "(%)", "<%>", '"%"', "ip: %, port 443", "addr|%|", "[%]:443", "%%eth0"])(
    "finds an address written as %s",
    (wrapper) => {
      expect(found(`conn ${wrapper.replace("%", "fe80::1")} up`)).toContain("fe80::1");
    },
  );

  // A separator that is not ASCII is still a separator. Unicode's own ID_Continue property is the
  // WRONG predicate here even though it reads like the right one: it deliberately admits connector
  // punctuation and the middle dots, because a language may allow them INSIDE an identifier. The
  // question this module asks is narrower — is the address standing on its own — so the bound is
  // built from letters, numbers, marks and the underscore instead. Losing an address is the worse
  // failure of the two: a suppressed token merges two different destinations, which is the whole
  // defect #640 exists to prevent, while an invented one only leaves two identical records
  // unmerged.
  it.each([
    ["U+00B7 middle dot", "\u00B7"],
    ["U+30FB katakana middle dot", "\u30FB"],
    ["U+FF65 halfwidth katakana middle dot", "\uFF65"],
    ["U+0387 Greek ano teleia", "\u0387"],
    ["U+FF0C fullwidth comma", "\uFF0C"],
    ["U+3001 ideographic comma", "\u3001"],
  ])("finds an address separated by %s", (_label, sep) => {
    expect(found(`peer${sep}fe80::1${sep}up`)).toContain("fe80::1");
  });

  it.each([
    ["hex-leading beside _", "conn_fe80::1_closed", "fe80::1"],
    ["colon-leading beside _", "conn_::1_closed", "::1"],
    ["v4-mapped beside _", "cap_::ffff:203.0.113.1_x", "::ffff:203"],
    ["hex-leading beside fullwidth _", "conn\uFF3F2001:db8::9\uFF3Fclosed", "2001:db8::9"],
    ["colon-leading beside undertie", "conn\u203F::1\u203Fclosed", "::1"],
  ])("never suppresses an address beside a connector — %s", (_label, text, addr) => {
    expect(found(text)).toContain(addr);
  });

  // A ":" was excluded from the boundary so a match could not start mid-address. That also made a
  // label colon suppress the address behind it — and "field:value" with no space is one of the most
  // ordinary shapes a log line takes. Suppression merges two destinations, so the colon is a
  // boundary now; the greedy match still takes the whole address rather than a tail of one.
  it.each([
    ["label, no space", "srcip:fe80::1 up", "fe80::1"],
    ["label, colon-leading address", "srcip:::1 up", "::1"],
    ["nested labels", "event:net:peer:fe80::1", "fe80::1"],
    ["quoted JSON value", '{"remote":"fe80::1"}', "fe80::1"],
    ["unquoted JSON value", '{"remote":fe80::1}', "fe80::1"],
  ])("finds an address behind a label colon — %s", (_label, text, addr) => {
    expect(found(text)).toContain(addr);
  });

  // The token is canonical however the line punctuated it: a LONE leading or trailing colon is the
  // label separator, not part of the address. "::1" and "1::" keep theirs, so the trim cannot eat a
  // compressed group. Without this the same destination written two ways yields two tokens, and two
  // records naming it fail to merge.
  it.each([
    ["trailing colon", "peer fe80::1: reset", "fe80::1"],
    ["leading colon", '{"remote":fe80::1}', "fe80::1"],
    ["loopback keeps its ::", "tgt ::1 x", "::1"],
    ["trailing :: is kept", "tgt 1:: x", "1::"],
  ])("returns a canonical token — %s", (_label, text, addr) => {
    expect(found(text)).toEqual([addr]);
  });

  // A colon count cannot tell an address from a counter: "01:02:03:04" has three colons and so does
  // nothing else about it say IPv6. Durations and timecodes are VOLATILE — they change every event
  // — so admitting one splits records that must merge. The token is validated as a real address
  // instead of counted, which is what makes the whole class of colon look-alikes impossible rather
  // than handled one at a time.
  it("keeps a fully expanded IPv6, which a colon count cannot distinguish from a counter", () => {
    expect(found("tgt 2001:0:0:0:0:0:0:1 x")).toContain("2001:0:0:0:0:0:0:1");
  });

  it("de-duplicates and sorts, so token order never depends on where they appeared", () => {
    expect(found("to 203.0.113.9 then 203.0.113.1 then 203.0.113.9")).toEqual(["203.0.113.1", "203.0.113.9"]);
  });

  it("rejects a dotted quad whose octets are out of range", () => {
    expect(found("build 999.888.777.666 shipped")).toEqual([]);
  });
});

describe("networkTokens — text that is NOT an address", () => {
  const found = (s: string): string[] => networkTokens(s.toLowerCase());

  it.each([
    ["a clock time", "heartbeat at 01:02:03 ok"],
    ["an ISO timestamp", "2026-01-01T00:00:00Z"],
    ["a PowerShell static call", "$x = [Convert]::FromBase64String($e)"],
    ["a C++ scope", "at std::vector::at offset 1024"],
    ["a Ruby scope", "Errno::ENOENT raised by Chef::Log"],
    ["nested scopes", "boost::asio::ip::tcp::socket"],
    ["a word before the ::", "handler foo::1234 completed"],
    ["an accented letter", "handler café::1234 done"],
    ["Hebrew", "handler משתמש::1234 done"],
    ["Cyrillic", "handler пользователь::1234 done"],
    ["CJK", "handler 用户::1234 done"],
    ["Greek", "handler χρήστης::1234 done"],
    ["a Windows path", "C:\\Windows\\Temp"],
    ["a four-field duration", "duration:01:02:03:04 elapsed"],
    ["a timecode", "timecode:00:00:01:23 mark"],
    ["a short elapsed counter", "elapsed:1:2:3:4 done"],
    ["an uptime counter", "uptime:0:00:00:01"],
    ["an unlabelled timecode", "runtime 01:02:03:04 total"],
    ["a lap counter", "lap:12:34:56:78 recorded"],
    ["a six-field counter", "seq:00:00:00:00:01:23 next"],
    ["a six-field date-time", "stamp:26:08:26:10:38:00 logged"],
    ["a MAC address", "mac 00:00:5e:00:53:01 seen"],
    ["a timestamp behind a label colon", "time:2026-01-01T00:00:00Z"],
  ])("ignores %s", (_label, text) => {
    expect(found(text)).toEqual([]);
  });

  // A COMBINING MARK is neither a letter nor a digit, so a class built from \p{L}\p{N}_ treated one
  // as a delimiter and the digits beside it became an address again. The same word decomposes to a
  // mark on macOS, whose filesystem stores names in NFD, so this is the ordinary case for anything
  // collected from a Mac — not an exotic one. Each string below is normalised to NFD explicitly so
  // the test cannot silently become a duplicate of the precomposed case above if an editor
  // recomposes the file.
  it.each([
    ["decomposed acute (café)", "handler café::1234 done"],
    ["decomposed ring (å)", "handler å::1234 done"],
    ["decomposed Vietnamese (tài)", "handler tài::1234 done"],
    ["decomposed Greek (χρήστης)", "handler χρήστης::1234 done"],
    ["Devanagari matra", "handler कि::1234 done"],
    ["Hebrew with niqqud", "handler מַשב::1234 done"],
  ])("ignores %s in NFD", (_label, text) => {
    const nfd = text.normalize("NFD");
    // The string really does carry a combining mark. Asserted on the MARK itself rather than on an
    // NFC round-trip: Devanagari and Hebrew-with-niqqud have no precomposed form, so NFC returns
    // them unchanged and a round-trip check would fail on a string that is perfectly decomposed.
    expect(/\p{M}/u.test(nfd)).toBe(true);
    expect(found(nfd)).toEqual([]);
  });

  // CONNECTOR PUNCTUATION: a chosen trade, pinned here so it reads as deliberate.
  //
  // A bound strict enough to reject "worker_::1234" also rejects "conn_::1", and no rule separates
  // them — both are an identifier, a connector and a valid IPv6 literal, and "::1" is loopback.
  // Splitting on token shape was tried and buys nothing: it rescues "conn_fe80::1" and still
  // suppresses "conn_::1". So connectors separate, and the invented token below is the cost.
  //
  // The two failures are not equal. Suppressing an address merges two different destinations —
  // the #640 defect, invisible to the analyst. Inventing a token leaves two identical records
  // unmerged — timeline noise the analyst can see. Never suppress.
  it("accepts an invented token beside a connector, as the cost of never suppressing one", () => {
    // NOT an address; this module cannot tell it from "conn_::1" and errs toward finding one.
    expect(found("handler worker_::1234 done")).toEqual(["::1234"]);
    expect(found("handler worker\uFF3F::1234 done")).toEqual(["::1234"]);
  });

  it("still reads a bare address-shaped token as an address", () => {
    // The rule is identifier-versus-standalone, not "does it look like an id". Nothing is attached
    // here, so it is a well-formed literal and treated as one — the forensic-safe reading.
    expect(found("handler 1234::1234 done")).toEqual(["1234::1234"]);
  });

  it("finds a real address in the same message as scope-resolution text", () => {
    expect(found("[Convert]::FromBase64String($x); std::vector::at; peer=fe80::9;")).toEqual(["fe80::9"]);
  });
});
