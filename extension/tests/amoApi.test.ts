import { describe, expect, it } from "vitest";
import { createHmac } from "node:crypto";

import {
  mintJwt,
  findVersion,
  versionsUrl,
  hasVersion,
  isAmoUrl,
  readNext,
  readCount,
  isReadableVersion,
  isValidAddonVersion,
  AMO_VERSION_RE,
} from "../scripts/amoApi.mjs";

describe("mintJwt", () => {
  it("produces a verifiable HS256 JWT", async () => {
    const token = await mintJwt("user:1:2", "s3cret", { now: 1_700_000_000, jti: "fixed" });
    const [head, body, sig] = token.split(".");
    expect(JSON.parse(Buffer.from(head, "base64url").toString())).toEqual({ alg: "HS256", typ: "JWT" });
    expect(JSON.parse(Buffer.from(body, "base64url").toString())).toEqual({
      iss: "user:1:2",
      jti: "fixed",
      iat: 1_700_000_000,
      exp: 1_700_000_240,
    });
    // The signature must actually verify. A JWT that merely LOOKS right fails at AMO, on a release.
    expect(sig).toBe(createHmac("sha256", "s3cret").update(`${head}.${body}`).digest("base64url"));
  });

  it("gives every request a distinct jti", async () => {
    // AMO rejects a replayed jti. Two calls in the same second must still differ.
    const a = await mintJwt("i", "s", { now: 1 });
    const b = await mintJwt("i", "s", { now: 1 });
    expect(a).not.toBe(b);
  });

  it("refuses to mint without credentials", async () => {
    await expect(mintJwt("", "s")).rejects.toThrow(/issuer and a secret/);
    await expect(mintJwt("i", "")).rejects.toThrow(/issuer and a secret/);
  });
});

describe("findVersion", () => {
  it("finds a version that is present", () => {
    const body = JSON.stringify({ results: [{ version: "0.36.0" }, { version: "0.35.1" }] });
    expect(findVersion(body, "0.36.0")).toMatchObject({ status: "yes" });
  });

  it("reports a genuine absence as no, and says what it did see", () => {
    const body = JSON.stringify({ results: [{ version: "0.35.1" }] });
    expect(findVersion(body, "0.36.0")).toMatchObject({ status: "no", seen: ["0.35.1"] });
  });

  it("treats an add-on with no versions as a genuine no", () => {
    expect(findVersion(JSON.stringify({ results: [] }), "0.36.0")).toMatchObject({ status: "no" });
  });

  // The three below are the whole reason this function exists rather than a `.find()` inline.
  // Every one of them would read as "not submitted yet" to a naive check, and the caller turns
  // that into "submit" — which on a re-run means submitting a version AMO already holds.

  it("treats an auth error as unknown, never as absent", () => {
    const result = findVersion(JSON.stringify({ detail: "Invalid token." }), "0.36.0");
    expect(result.status).toBe("unknown");
    expect(result.reason).toBe("Invalid token.");
  });

  it("treats a non-JSON body as unknown", () => {
    expect(findVersion("<html>502 Bad Gateway</html>", "0.36.0")).toMatchObject({ status: "unknown" });
  });

  it("treats a results field that is not an array as unknown", () => {
    expect(findVersion(JSON.stringify({ results: null }), "0.36.0").status).toBe("unknown");
    expect(findVersion("null", "0.36.0").status).toBe("unknown");
  });

  it("still reports a hit when other entries are malformed", () => {
    // Precedence, not luck: the version IS there, so nothing is left to be uncertain about.
    const body = JSON.stringify({ results: [null, { version: 42 }, { version: "0.36.0" }] });
    expect(findVersion(body, "0.36.0")).toMatchObject({ status: "yes" });
  });

  it("refuses to call it absent when an entry's version could not be read", () => {
    // The entry it could not read might BE the version sought. Answering "no" here is what makes
    // the caller submit a version AMO may already hold.
    const body = JSON.stringify({ results: [null, { version: "0.40.0" }] });
    const result = findVersion(body, "0.36.0");
    expect(result.status).toBe("unknown");
    expect(result.reason).toContain("1 of 2 entries");
  });

  it.each([
    ["null", null],
    ["a number version", { version: 42 }],
    ["a missing version key", { id: 7 }],
    ["a string instead of an object", "0.36.0"],
  ])("treats an entry that is %s as unreadable", (_label, entry) => {
    const body = JSON.stringify({ results: [entry, { version: "0.40.0" }] });
    expect(findVersion(body, "0.36.0").status).toBe("unknown");
  });

  it("reports only genuinely readable versions in seen", () => {
    // `seen` feeds the count reconciliation. A placeholder for an unread entry would pad it and
    // make a short list reconcile against the server's total.
    const body = JSON.stringify({ results: [null, { version: "0.40.0" }] });
    expect(findVersion(body, "0.36.0").seen).toEqual(["0.40.0"]);
  });

  it("matches the version exactly, not by prefix", () => {
    // "0.3" must not match "0.36.0", and "0.36.0" must not be satisfied by "0.36.0-beta".
    const body = JSON.stringify({ results: [{ version: "0.36.0-beta" }] });
    expect(findVersion(body, "0.36.0")).toMatchObject({ status: "no" });
    expect(findVersion(JSON.stringify({ results: [{ version: "0.36.0" }] }), "0.3").status).toBe("no");
  });
});

describe("versionsUrl", () => {
  it("asks for unlisted and in-review versions too", () => {
    // A freshly uploaded version is not public until a reviewer approves it. Without this filter
    // the check would report "not submitted" for something submitted minutes ago.
    expect(versionsUrl("a@b")).toContain("filter=all_with_unlisted");
  });

  it("encodes the add-on id, which contains an @", () => {
    expect(versionsUrl("dfir-companion@hasamba.github.io")).toContain("dfir-companion%40hasamba.github.io");
  });
});

describe("hasVersion paging", () => {
  // The endpoint paginates at 25. Reading page one and calling it absent is wrong the moment the
  // add-on has 26 versions, and wrong in the direction that costs a release: "no" means "submit",
  // and AMO then rejects the duplicate.
  // `total` defaults to this page's own length, i.e. a single-page list. Multi-page fixtures pass
  // the real total — a body claiming more versions than the walk ever sees is itself a tested case
  // below, not something every fixture should assert by accident.
  const page = (versions: string[], next: string | null, total = versions.length) =>
    JSON.stringify({ count: total, next, results: versions.map((version) => ({ version })) });

  const fakeFetch = (pages: Record<string, string>) => {
    const calls: string[] = [];
    const impl = (async (url: string) => {
      calls.push(String(url));
      const body = pages[String(url)];
      if (body === undefined) throw new Error(`unexpected url ${url}`);
      return { text: async () => body };
    }) as unknown as typeof fetch;
    return { impl, calls };
  };

  const FIRST = versionsUrl("a@b");
  const SECOND = "https://addons.mozilla.org/api/v5/addons/addon/a%40b/versions/?page=2";

  it("finds a version that only appears on the second page", async () => {
    const { impl, calls } = fakeFetch({
      [FIRST]: page(["0.40.0", "0.39.0"], SECOND, 4),
      [SECOND]: page(["0.36.0", "0.35.1"], null, 4),
    });
    const result = await hasVersion({ addonId: "a@b", version: "0.36.0", token: "t", fetchImpl: impl });
    expect(result.status).toBe("yes");
    expect(result.pages).toBe(2);
    expect(calls).toEqual([FIRST, SECOND]);
  });

  it("stops paging as soon as it finds the version", async () => {
    const { impl, calls } = fakeFetch({ [FIRST]: page(["0.36.0"], SECOND) });
    const result = await hasVersion({ addonId: "a@b", version: "0.36.0", token: "t", fetchImpl: impl });
    expect(result.status).toBe("yes");
    expect(calls).toEqual([FIRST]); // never asked for page 2
  });

  it("only says no after the whole list is exhausted", async () => {
    const { impl } = fakeFetch({
      [FIRST]: page(["0.40.0"], SECOND, 2),
      [SECOND]: page(["0.39.0"], null, 2),
    });
    const result = await hasVersion({ addonId: "a@b", version: "0.36.0", token: "t", fetchImpl: impl });
    expect(result).toMatchObject({ status: "no", pages: 2 });
    expect(result.seen).toEqual(["0.40.0", "0.39.0"]);
  });

  it("reports unknown when a later page fails, never no", async () => {
    // The dangerous case: page 1 parsed fine, so a naive implementation would answer from it.
    const { impl } = fakeFetch({
      [FIRST]: page(["0.40.0"], SECOND, 2),
      [SECOND]: '{"detail":"Internal Server Error"}',
    });
    const result = await hasVersion({ addonId: "a@b", version: "0.36.0", token: "t", fetchImpl: impl });
    expect(result.status).toBe("unknown");
    expect(result.reason).toContain("Internal Server Error");
  });

  it("reports unknown when a page request throws", async () => {
    const impl = (async () => {
      throw new Error("ECONNRESET");
    }) as unknown as typeof fetch;
    const result = await hasVersion({ addonId: "a@b", version: "0.36.0", token: "t", fetchImpl: impl });
    expect(result).toMatchObject({ status: "unknown" });
    expect(result.reason).toContain("ECONNRESET");
  });

  it("refuses to follow a next link that is not AMO", async () => {
    // `next` is data from a response, not an instruction. Following it anywhere would send the
    // developer's JWT to whatever host the body named.
    const { impl, calls } = fakeFetch({
      [FIRST]: page(["0.40.0"], "https://evil.example/api/v5/versions/?page=2", 2),
    });
    const result = await hasVersion({ addonId: "a@b", version: "0.36.0", token: "t", fetchImpl: impl });
    expect(result.status).toBe("unknown");
    expect(result.reason).toContain("off-site");
    expect(calls).toEqual([FIRST]); // the JWT never left AMO
  });

  it("gives up with unknown rather than looping forever", async () => {
    // A server that always returns a `next` must not spin the job until its timeout.
    const selfReferential = (async () => ({ text: async () => page(["0.1.0"], FIRST, 999) })) as unknown as typeof fetch;
    const result = await hasVersion({
      addonId: "a@b",
      version: "0.36.0",
      token: "t",
      fetchImpl: selfReferential,
      maxPages: 3,
    });
    expect(result).toMatchObject({ status: "unknown", pages: 3 });
    expect(result.reason).toContain("3 pages");
  });
});

describe("isAmoUrl", () => {
  it("accepts AMO and rejects everything else", () => {
    expect(isAmoUrl("https://addons.mozilla.org/api/v5/x")).toBe(true);
    expect(isAmoUrl("http://addons.mozilla.org/api/v5/x")).toBe(false); // downgrade to http
    expect(isAmoUrl("https://addons.mozilla.org.evil.example/x")).toBe(false); // suffix trick
    expect(isAmoUrl("https://evil.example/x")).toBe(false);
    expect(isAmoUrl("not a url")).toBe(false);
  });
});

describe("malformed pagination metadata", () => {
  // Every case here used to produce a confident "no", because `next` was read as "truthy string or
  // the list ended". A definitive absence is the answer that makes the caller SUBMIT, so a
  // response this code cannot interpret must never reach it.
  const body = (extra: Record<string, unknown>) =>
    JSON.stringify({ count: 1, results: [{ version: "0.40.0" }], ...extra });

  const walk = async (raw: string) => {
    const impl = (async () => ({ text: async () => raw })) as unknown as typeof fetch;
    return hasVersion({ addonId: "a@b", version: "0.36.0", token: "t", fetchImpl: impl });
  };

  it.each([
    ["a number", 42],
    ["an object", {}],
    ["an array", []],
    ["a boolean", true],
    ["an empty string", ""],
  ])("treats next being %s as unknown, not as the end of the list", async (_label, next) => {
    expect(readNext(body({ next })).kind).toBe("malformed");
    expect((await walk(body({ next }))).status).toBe("unknown");
  });

  it.each([
    ["null", null],
    ["absent", undefined],
  ])("treats next being %s as a genuine end of list", async (_label, next) => {
    const raw = next === undefined ? body({}) : body({ next });
    expect(readNext(raw).kind).toBe("end");
    expect((await walk(raw)).status).toBe("no");
  });

  it("refuses to call it absent when the server counted more than it returned", async () => {
    // 99 declared, 1 delivered, no next link. The list plainly did not finish, so "not there"
    // is not a conclusion available from it.
    const raw = JSON.stringify({ count: 99, next: null, results: [{ version: "0.40.0" }] });
    const result = await walk(raw);
    expect(result.status).toBe("unknown");
    expect(result.reason).toContain("1 version(s) but the server reported 99");
  });

  it.each([
    ["a string", "99"],
    ["a fraction", 1.5],
    ["negative", -1],
  ])("treats count being %s as unknown", async (_label, count) => {
    const raw = JSON.stringify({ count, next: null, results: [{ version: "0.40.0" }] });
    expect(readCount(raw).kind).toBe("malformed");
    expect((await walk(raw)).status).toBe("unknown");
  });

  it("still answers when count is absent entirely", async () => {
    // A missing optional field must not make the pre-flight useless — the `next` chain remains the
    // primary signal, and it said the list ended.
    const raw = JSON.stringify({ next: null, results: [{ version: "0.40.0" }] });
    expect(readCount(raw).kind).toBe("absent");
    expect((await walk(raw)).status).toBe("no");
  });

  it("accepts a count that agrees with what was read", async () => {
    const raw = JSON.stringify({ count: 1, next: null, results: [{ version: "0.40.0" }] });
    expect((await walk(raw)).status).toBe("no");
  });

  it("does not reconcile the count when the version was found", async () => {
    // Finding it is definitive. A bogus count must not turn a hit into a stop.
    const raw = JSON.stringify({ count: 999, next: null, results: [{ version: "0.36.0" }] });
    expect((await walk(raw)).status).toBe("yes");
  });
});

describe("unreadable entries and the count reconciliation", () => {
  const walk = async (raw: string) => {
    const impl = (async () => ({ text: async () => raw })) as unknown as typeof fetch;
    return hasVersion({ addonId: "a@b", version: "0.36.0", token: "t", fetchImpl: impl });
  };

  it("does not let placeholders satisfy the server's count", async () => {
    // Two entries, one unreadable, count: 2, no next page. Counting the unreadable one would make
    // the totals agree and produce a confident "not there" from a list half of which was unread.
    const raw = JSON.stringify({ count: 2, next: null, results: [null, { version: "0.40.0" }] });
    const result = await walk(raw);
    expect(result.status).toBe("unknown");
    expect(result.reason).toContain("readable version string");
  });

  it("stops on the page with the unreadable entry rather than paging past it", async () => {
    const raw = JSON.stringify({ count: 9, next: "https://addons.mozilla.org/x", results: [{ id: 1 }] });
    const result = await walk(raw);
    expect(result).toMatchObject({ status: "unknown", pages: 1 });
  });

  it("accumulates only readable versions across pages", async () => {
    const FIRST = versionsUrl("a@b");
    const SECOND = "https://addons.mozilla.org/api/v5/addons/addon/a%40b/versions/?page=2";
    const impl = (async (url: string) => ({
      text: async () =>
        String(url) === FIRST
          ? JSON.stringify({ count: 2, next: SECOND, results: [{ version: "0.40.0" }] })
          : JSON.stringify({ count: 2, next: null, results: [{ version: "0.39.0" }] }),
    })) as unknown as typeof fetch;
    const result = await hasVersion({ addonId: "a@b", version: "0.36.0", token: "t", fetchImpl: impl });
    expect(result).toMatchObject({ status: "no", seen: ["0.40.0", "0.39.0"] });
  });
});

describe("blank version strings", () => {
  // `""` is a string, and that was the whole problem: it passed a typeof check, entered the list
  // of versions read, and let a page whose entry was never really read produce a confident
  // absence — while padding that list so the server's count reconciled. readNext has always held
  // empty strings to this standard; these assert the same rule where it was missing.
  const walk = async (raw: string) => {
    const impl = (async () => ({ text: async () => raw })) as unknown as typeof fetch;
    return hasVersion({ addonId: "a@b", version: "0.36.0", token: "t", fetchImpl: impl });
  };

  it.each([
    ["empty", ""],
    ["a single space", " "],
    ["whitespace", "   \t "],
  ])("treats an entry whose version is %s as unread", async (_label, version) => {
    const raw = JSON.stringify({ count: 2, next: null, results: [{ version }, { version: "0.40.0" }] });
    const result = await walk(raw);
    expect(result.status).toBe("unknown");
    expect(result.seen).toEqual(["0.40.0"]);
  });

  it("does not let a blank entry pad the count", async () => {
    // count 2, two entries, one blank. Counting the blank one makes the totals agree and yields a
    // definitive "not there" from a list half of which was never read.
    const raw = JSON.stringify({ count: 2, next: null, results: [{ version: "" }, { version: "0.40.0" }] });
    expect((await walk(raw)).status).toBe("unknown");
  });

  it("refuses to be asked about a blank version", () => {
    // Not a server problem — a programming error, and a quiet one: a blank sought version
    // "matches" a blank entry, and against a healthy list returns a confident absence.
    for (const bad of ["", " ", "\n"]) {
      expect(() => findVersion(JSON.stringify({ results: [] }), bad)).toThrow(TypeError);
    }
  });

  it("still finds a real version on a page that also has a blank one", () => {
    const raw = JSON.stringify({ results: [{ version: "" }, { version: "0.36.0" }] });
    expect(findVersion(raw, "0.36.0").status).toBe("yes");
  });
});

describe("isReadableVersion", () => {
  it("accepts a real version and rejects every blank shape", () => {
    expect(isReadableVersion("0.36.0")).toBe(true);
    expect(isReadableVersion("")).toBe(false);
    expect(isReadableVersion("   ")).toBe(false);
    expect(isReadableVersion(undefined)).toBe(false);
    expect(isReadableVersion(null)).toBe(false);
    expect(isReadableVersion(42)).toBe(false);
  });
});

describe("isValidAddonVersion", () => {
  // Mozilla's rule, quoted from the MDN `version` page rather than invented: one to four
  // dot-separated numbers, digits only, at most nine digits per part, no leading zeros except a
  // bare 0. The first five valid and the two invalid cases are MDN's own examples.
  it.each(["0.2", "1.2.3", "2.0.1", "2.10", "1.2.3.4", "0", "0.36.0", "999999999.1"])(
    "accepts %s",
    (version) => {
      expect(isValidAddonVersion(version)).toBe(true);
    },
  );

  it.each([
    ["2.01", "leading zero"],
    ["1.2.3.4.5", "five parts"],
    ["1234567890.1", "ten digits in a part"],
    ["0abc.9xyz", "letters, which the old shell glob accepted"],
    ["1.2 && curl evil.example", "a shell fragment, which the old glob also accepted"],
    ["1.2-beta", "a prerelease suffix — version_name is the field for that"],
    ["1.", "a trailing dot"],
    [".1", "a leading dot"],
    ["1..2", "an empty part"],
    ["v1.2.3", "a v prefix"],
    [" 1.2", "leading whitespace"],
    ["1.2 ", "trailing whitespace"],
    ["undefined", "what `node -p` prints for a missing key"],
    ["", "empty"],
    ["   ", "blank"],
  ])("rejects %s (%s)", (version) => {
    expect(isValidAddonVersion(version)).toBe(false);
  });

  it.each([undefined, null, 42, {}, ["1.2.3"]])("rejects the non-string %s", (value) => {
    expect(isValidAddonVersion(value as unknown as string)).toBe(false);
  });

  it("is anchored at both ends", () => {
    // An unanchored regex would match the digits inside anything, which is how a validator ends up
    // approving a string that merely contains a version.
    expect(AMO_VERSION_RE.source.startsWith("^")).toBe(true);
    expect(AMO_VERSION_RE.source.endsWith("$")).toBe(true);
  });

  it("accepts the version this repository actually ships", async () => {
    // Ties the rule to reality: a validator that rejects our own manifest would fail every release
    // rather than protect one.
    const { readFileSync } = await import("node:fs");
    const manifest = JSON.parse(readFileSync(new URL("../manifest.json", import.meta.url), "utf8"));
    expect(isValidAddonVersion(manifest.version)).toBe(true);
  });
});
