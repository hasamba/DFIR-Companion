import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  deriveKnownEntities,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

// #3007: a profile path followed by a very long line on the same line was learned as ONE username,
// and the bare-name pass compiled it into one regex literal. V8 overflows the stack compiling a
// literal of ~12k letters under "iu", so the first apply() threw — and because the name is learned
// from the forensic timeline on every call, every masked AI call for the case threw.

const NONE: KnownEntities = { hosts: [], accounts: [], internalDomains: [] };
function policy(): AnonPolicy {
  return {
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
      CARD: false,
      PHONE: false,
      NATID: false,
    },
  };
}
// The profile prefix is built from parts, so no literal profile path sits in the source.
const PROFILE = ["C:", "Users", ""].join("\\");
const words = (n: number, stem = "lorem") =>
  Array.from({ length: n }, (_, i) => stem + "abcdefghij"[i % 10]).join(" ");

describe("a very long learned username never overflows the stack (#3007)", () => {
  it("masks a profile segment of 8000 words whole and restores it", () => {
    const name = `jdoe ${words(8000)}`;
    const text = `${PROFILE}${name}`;
    const a = createAnonymizer(policy(), NONE);
    const out = a.apply(text);
    expect(out).toBe(`${PROFILE}ANON_USER_1`);
    expect(a.restore(out)).toBe(text);
  });

  it("keeps every masked call working when the long name sits in the forensic timeline", () => {
    const s = emptyState("c1");
    s.forensicTimeline = [
      {
        id: "e1",
        timestamp: "2026-01-01T00:00:00Z",
        description: `Process started from ${PROFILE}jdoe ${words(3000)}`,
        severity: "High",
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
      },
    ];
    const a = createAnonymizer(policy(), deriveKnownEntities(s));
    expect(a.apply("the user ran whoami")).toBe("the user ran whoami");
  });

  it("masks a bare repeat of a long learned name, in any case, with the path's token", () => {
    const name = `jdoe ${words(3000)}`;
    const text = `${PROFILE}${name}\\x then ${name.toUpperCase()} said hi`;
    const a = createAnonymizer(policy(), NONE);
    const out = a.apply(text);
    expect(out).toBe(`${PROFILE}ANON_USER_1\\x then ANON_USER_1 said hi`);
    expect(a.restore(out).toLowerCase()).toBe(text.toLowerCase());
  });

  it("matches across a chunk boundary case-insensitively (Kelvin sign and k)", () => {
    // 255 letters, then "k" at code point 256, so the chunk boundary falls next to it.
    const name = "a".repeat(255) + "k" + "b".repeat(300);
    const bare = "A".repeat(255) + "\u212A" + "B".repeat(300);
    const a = createAnonymizer(policy(), { ...NONE, usernames: [name] });
    expect(a.apply(`x ${bare} y`)).toBe("x ANON_USER_1 y");
  });

  it("keeps the whole-word boundary of a long name", () => {
    const name = "q".repeat(600);
    const a = createAnonymizer(policy(), { ...NONE, usernames: [name] });
    expect(a.apply(`${name}s and x${name}`)).toBe(`${name}s and x${name}`);
  });

  it("picks the leftmost match first, then the longest, as the single regex did", () => {
    // With "ann bob" and a long name starting "bob carol", the earlier start wins; the short-name
    // span is masked and the scan resumes after it, exactly as before the long name was chunked.
    const long = `bob carol ${words(80, "dave")}`;
    const a = createAnonymizer(policy(), { ...NONE, usernames: ["ann bob", long] });
    expect(a.apply(`hi ann bob x and ${long} y`)).toBe("hi ANON_USER_1 x and ANON_USER_2 y");
  });
});
