import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ServerSetStore } from "../../src/integrations/serverSets/serverSetStore.js";
import { open, seal, deriveServerSetKey } from "../../src/integrations/serverSets/secretBox.js";
import {
  incompleteTools,
  MASKED_SECRET,
  maskServerSet,
  type ServerSetInput,
} from "../../src/integrations/serverSets/types.js";

const KEY = Buffer.alloc(32, 7);
const input = (): ServerSetInput => ({
  name: "lab",
  iris: {
    url: "https://iris.example.com",
    apiKey: "iris-key-sentinel-alpha",
    customerId: "1",
    insecure: true,
  },
  timesketch: {
    url: "https://ts.example.com",
    user: "analyst",
    password: "ts-pass-sentinel-beta",
    timeline: "main",
  },
  velociraptor: { apiConfigPath: "/etc/vr/api.yaml", org: "O123", guiUrl: "https://vr.example.com" },
});

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "serversets-"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("ServerSetStore", () => {
  it("create then get round-trips every field", () => {
    const s = new ServerSetStore(dir, KEY);
    const made = s.create(input());
    expect(made.revision).toBe(1);
    expect(s.get(made.id)).toEqual({ ...input(), id: made.id, revision: 1 });
    expect(s.list()).toHaveLength(1);
  });

  it("secrets are sealed on disk", () => {
    const s = new ServerSetStore(dir, KEY);
    s.create(input());
    const raw = readFileSync(join(dir, "sets.json"), "utf8");
    expect(raw).not.toContain("iris-key-sentinel-alpha");
    expect(raw).not.toContain("ts-pass-sentinel-beta");
    expect(raw).toContain("v1:");
  });

  it("masked secret in update keeps the stored value", () => {
    const s = new ServerSetStore(dir, KEY);
    const made = s.create(input());
    const next = s.update(made.id, { ...input(), iris: { ...input().iris!, apiKey: MASKED_SECRET } });
    expect(next.revision).toBe(2);
    expect(s.get(made.id)!.iris!.apiKey).toBe("iris-key-sentinel-alpha");
    s.update(made.id, { ...input(), iris: { ...input().iris!, apiKey: "iris-key-sentinel-gamma" } });
    expect(s.get(made.id)!.iris!.apiKey).toBe("iris-key-sentinel-gamma");
  });

  it("wrong key cannot open", () => {
    const made = new ServerSetStore(dir, KEY).create(input());
    const other = new ServerSetStore(dir, Buffer.alloc(32, 9));
    expect(() => other.get(made.id)).toThrow(/cannot decrypt/);
  });

  it("remove refuses a set in use", () => {
    const s = new ServerSetStore(dir, KEY);
    const made = s.create(input());
    s.linkCase("c1", made.id);
    expect(s.remove(made.id)).toEqual({ ok: false, usedBy: ["c1"] });
    s.unlinkCase("c1");
    expect(s.remove(made.id)).toEqual({ ok: true });
    expect(s.get(made.id)).toBeUndefined();
  });

  it("remove refuses the default set", () => {
    const s = new ServerSetStore(dir, KEY);
    const made = s.create(input());
    s.setDefault(made.id);
    expect(s.defaultId()).toBe(made.id);
    expect(s.remove(made.id)).toEqual({ ok: false, usedBy: [] });
  });

  it("sees changes made by another instance", () => {
    const a = new ServerSetStore(dir, KEY);
    const b = new ServerSetStore(dir, KEY);
    const made = a.create(input());
    a.linkCase("c9", made.id);
    expect(b.get(made.id)?.name).toBe("lab");
    expect(b.caseSetId("c9")).toBe(made.id);
    expect(b.casesUsing(made.id)).toEqual(["c9"]);
  });

  it("name is unique and 1-80 chars", () => {
    const s = new ServerSetStore(dir, KEY);
    s.create(input());
    expect(() => s.create(input())).toThrow("name already used");
    expect(() => s.create({ ...input(), name: "  " })).toThrow("name required");
    expect(() => s.create({ ...input(), name: "x".repeat(81) })).toThrow(/80/);
  });

  it("create rejects a masked secret", () => {
    const s = new ServerSetStore(dir, KEY);
    expect(() =>
      s.create({ name: "a", iris: { url: "https://iris.example.com", apiKey: MASKED_SECRET } }),
    ).toThrow("secret required");
    expect(() =>
      s.create({
        name: "b",
        timesketch: { url: "https://ts.example.com", user: "u", password: MASKED_SECRET },
      }),
    ).toThrow("secret required");
    expect(s.list()).toHaveLength(0);
  });

  it("rejects non http(s) urls", () => {
    const s = new ServerSetStore(dir, KEY);
    expect(() => s.create({ name: "a", iris: { url: "ftp://x", apiKey: "k" } })).toThrow(
      "iris url must be http(s)",
    );
    expect(() => s.create({ name: "b", timesketch: { url: "nope", user: "u", password: "p" } })).toThrow(
      "timesketch url must be http(s)",
    );
  });
});

describe("types helpers", () => {
  it("incompleteTools flags a URL with no key", () => {
    expect(incompleteTools({ name: "x", iris: { url: "https://iris.example.com", apiKey: "" } })).toEqual([
      "iris",
    ]);
    expect(incompleteTools({ name: "x" })).toEqual([]);
    expect(incompleteTools({ name: "x", iris: { url: "", apiKey: "" } })).toEqual([]);
    expect(incompleteTools({ name: "x", velociraptor: { apiConfigPath: "", org: "o" } })).toEqual([
      "velociraptor",
    ]);
  });

  it("maskServerSet hides secrets", () => {
    const m = maskServerSet({ ...input(), id: "i", revision: 1 });
    expect(m.iris!.apiKey).toBe(MASKED_SECRET);
    expect(m.timesketch!.password).toBe(MASKED_SECRET);
    expect(m.iris!.url).toBe("https://iris.example.com");
    expect(m.timesketch!.user).toBe("analyst");
  });
});

describe("secretBox", () => {
  it("round-trips and derives a 32-byte key", () => {
    const k = deriveServerSetKey(Buffer.from("instance-secret"));
    expect(k).toHaveLength(32);
    const sealed = seal("hello", k);
    expect(sealed.split(":")).toHaveLength(4);
    expect(open(sealed, k)).toBe("hello");
    expect(seal("hello", k)).not.toBe(sealed);
  });

  it("refuses a truncated auth tag, even one that is a correct prefix of the real tag", () => {
    const k = deriveServerSetKey(Buffer.from("instance-secret"));
    const [v, iv, tag, ct] = seal("hello", k).split(":");
    const short = Buffer.from(tag, "base64").subarray(0, 4).toString("base64");
    expect(() => open([v, iv, short, ct].join(":"), k)).toThrow(/cannot decrypt/);
  });
});

describe("links with prototype-named case ids", () => {
  it("a case id like 'constructor' or '__proto__' has no set until linked", () => {
    const store = new ServerSetStore(dir, KEY);
    const a = store.create({ name: "A" });
    for (const id of ["constructor", "__proto__", "toString", "hasOwnProperty"]) {
      expect(store.caseSetId(id)).toBeUndefined();
    }
    expect(store.casesUsing(a.id)).toEqual([]);
    store.linkCase("constructor", a.id);
    expect(store.caseSetId("constructor")).toBe(a.id);
    expect(store.casesUsing(a.id)).toEqual(["constructor"]);
    expect(store.caseSetId("toString")).toBeUndefined();
  });
});
