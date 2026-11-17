import { describe, expect, it, beforeEach } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AnonMapStore, ANON_MAP_MAX } from "../../src/analysis/anonMap.js";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";

// #2657: one saved masking map per case. Allocation happens under a per-case lock at mask time, so
// the token a call sends is the token the map saves.

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
    PATH: false,
    CMD: false,
    REG: false,
    CARD: false,
    PHONE: false,
    NATID: false,
  },
};

let cases: CaseStore;
let store: AnonMapStore;
const file = () => join(cases.stateDir("c1"), "anon-map.json");

/** Mask `text` naming `hosts`, the way a send seam does. */
const send = (hosts: string[], text: string) =>
  store.withAnonMap("c1", async (identity) => {
    const anon = createAnonymizer(POLICY, { hosts, accounts: [], internalDomains: [] }, [], identity);
    return { anon, result: anon.apply(text) };
  });

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-anonmap-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new AnonMapStore(cases);
});

describe("AnonMapStore (#2657)", () => {
  it("a value keeps its token across separate calls; a new one numbers above", async () => {
    expect(await send(["ws-02"], "on ws-02")).toBe("on ANON_HOST_1");
    expect(await send(["fs-09", "ws-02"], "fs-09 then ws-02")).toBe("ANON_HOST_2 then ANON_HOST_1");
    expect((await store.load("c1")).pairs.map((p) => p.token)).toEqual(["ANON_HOST_1", "ANON_HOST_2"]);
  });

  it("concurrent calls on one case never share a token for different values, and saved == sent", async () => {
    const [a, b] = await Promise.all([send(["host-a"], "host-a"), send(["host-b"], "host-b")]);
    expect(a).not.toBe(b);
    const saved = new Map((await store.load("c1")).pairs.map((p) => [p.value, p.token]));
    expect(saved.get("host-a")).toBe(a);
    expect(saved.get("host-b")).toBe(b);
  });

  it("drops malformed entries on load: bad token, mismatched category, duplicates", async () => {
    await writeFile(
      file(),
      JSON.stringify({
        version: 1,
        pairs: [
          { token: "ANON_HOST_1", value: "ws-02", category: "HOST" },
          { token: "ANON_HOST_1", value: "other", category: "HOST" },
          { token: "ANON_HOST_2", value: "WS-02", category: "HOST" },
          { token: "ANON_IP_3", value: "x", category: "HOST" },
          { token: "bogus", value: "y", category: "HOST" },
          { token: "ANON_USER_4", value: "", category: "USER" },
        ],
      }),
    );
    expect((await store.load("c1")).pairs).toEqual([
      { token: "ANON_HOST_1", value: "ws-02", category: "HOST" },
    ]);
  });

  it("a corrupt file is left as it is, and masking still works", async () => {
    await writeFile(file(), "{not json");
    expect(await send(["ws-02"], "on ws-02")).toBe("on ANON_HOST_1");
    expect(await readFile(file(), "utf8")).toBe("{not json");
  });

  it("past the cap, new values still mask but are not saved", async () => {
    const full = Array.from({ length: ANON_MAP_MAX }, (_, i) => ({
      token: `ANON_HOST_${i + 1}`,
      value: `h${i}`,
      category: "HOST",
    }));
    await writeFile(file(), JSON.stringify({ version: 1, pairs: full }));
    expect(await send(["new-host"], "new-host")).toBe(`ANON_HOST_${ANON_MAP_MAX + 1}`);
    expect((await store.load("c1")).pairs).toHaveLength(ANON_MAP_MAX);
  });
});
