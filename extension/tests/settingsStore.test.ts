import { describe, expect, it } from "vitest";
import {
  isExtensionPageSender,
  mergeSettingsPatch,
  sanitizeSettingsExpectation,
  sanitizeSettingsPatch,
  SerialQueue,
  SettingsReconciler,
  settingsChangeNeedsReconcile,
  SettingsWriter,
  type SettingsArea,
} from "../src/settingsStore.js";
import { requestSettingsUpdate } from "../src/settingsClient.js";
import { DEFAULT_SETTINGS, type Settings } from "../src/types.js";

// A storage area whose reads and writes yield to the event loop, so concurrent callers really do
// interleave unless something orders them.
function fakeArea(initial?: Partial<Settings>): SettingsArea & { data: Record<string, unknown>; writes: number } {
  const area = {
    data: initial ? { settings: { ...DEFAULT_SETTINGS, ...initial } } : ({} as Record<string, unknown>),
    writes: 0,
    async get(key: string) {
      await new Promise((r) => setTimeout(r, 1));
      return key in area.data ? { [key]: structuredClone(area.data[key]) } : {};
    },
    async set(items: Record<string, unknown>) {
      await new Promise((r) => setTimeout(r, 1));
      area.writes += 1;
      Object.assign(area.data, structuredClone(items));
    },
  };
  return area;
}

const stored = (area: { data: Record<string, unknown> }) => area.data.settings as Settings;

describe("SettingsWriter — #2398 writers change only their own fields", () => {
  it("an options-page save of URL and token keeps a Start made after the page opened", async () => {
    const area = fakeArea({ caseId: "CASE-A", running: false });
    const writer = new SettingsWriter(area);
    await writer.update({ caseId: "CASE-B", running: true }); // popup Start
    await writer.update({ companionUrl: "http://127.0.0.1:9000", serviceToken: "tok" }); // options Save
    expect(stored(area)).toMatchObject({
      caseId: "CASE-B", running: true, companionUrl: "http://127.0.0.1:9000", serviceToken: "tok",
    });
  });

  it("orders concurrent writes so neither is lost", async () => {
    const area = fakeArea({ caseId: "CASE-A" });
    const writer = new SettingsWriter(area);
    await Promise.all([
      writer.update({ running: true }),
      writer.update({ serviceToken: "tok" }),
      writer.update({ intervalSeconds: 60 }),
    ]);
    expect(stored(area)).toMatchObject({ caseId: "CASE-A", running: true, serviceToken: "tok", intervalSeconds: 60 });
  });

  it("a toggle decided inside the transaction sees the latest state", async () => {
    const area = fakeArea({ caseId: "CASE-A", running: false });
    const writer = new SettingsWriter(area);
    const seen: boolean[] = [];
    const toggle = () => writer.transact(async (cur) => { seen.push(cur.running); return { running: !cur.running }; });
    await Promise.all([toggle(), toggle(), toggle()]);
    expect(seen).toEqual([false, true, false]);
    expect(stored(area).running).toBe(true);
  });

  it("a transaction that decides nothing writes nothing", async () => {
    const area = fakeArea({ caseId: "CASE-A" });
    const result = await new SettingsWriter(area).transact(async () => undefined);
    expect(result.applied).toBe(false);
    expect(area.writes).toBe(0);
  });

  it("a failed write does not block the next one", async () => {
    const area = fakeArea({ caseId: "CASE-A" });
    const writer = new SettingsWriter(area);
    const failing = writer.transact(async () => { throw new Error("quota"); });
    const next = writer.update({ serviceToken: "tok" });
    await expect(failing).rejects.toThrow("quota");
    await expect(next).resolves.toMatchObject({ applied: true });
    expect(stored(area).serviceToken).toBe("tok");
  });

  it("compare-and-set: a late case check does not clear a case picked since", async () => {
    const area = fakeArea({ caseId: "CASE-B", running: true });
    const writer = new SettingsWriter(area);
    const result = await writer.update({ caseId: "" }, { caseId: "CASE-A" });
    expect(result.applied).toBe(false);
    expect(stored(area)).toMatchObject({ caseId: "CASE-B", running: true });
  });

  it("compare-and-set: a late answer from the old companion does not clear the case on the new one", async () => {
    const area = fakeArea({ caseId: "CASE-A", running: true, companionUrl: "http://old:1", serviceToken: "t1" });
    const writer = new SettingsWriter(area);
    const checked = { caseId: "CASE-A", companionUrl: "http://old:1", serviceToken: "t1" };
    await writer.update({ companionUrl: "http://new:1" }); // analyst switches server while the list loads
    const result = await writer.update({ caseId: "" }, checked);
    expect(result.applied).toBe(false);
    expect(stored(area)).toMatchObject({ caseId: "CASE-A", running: true, companionUrl: "http://new:1" });
    await writer.update({ companionUrl: "http://old:1", serviceToken: "t2" }); // or changes the token
    expect((await writer.update({ caseId: "" }, checked)).applied).toBe(false);
  });

  it("compare-and-set: clearing the checked case stops capture and says so", async () => {
    const area = fakeArea({ caseId: "CASE-A", running: true });
    const result = await new SettingsWriter(area).update({ caseId: "" }, { caseId: "CASE-A" });
    expect(result).toMatchObject({ applied: true, stoppedForNoCase: true });
    expect(stored(area)).toMatchObject({ caseId: "", running: false });
  });

  it("reads defaults when nothing is stored", async () => {
    expect(await new SettingsWriter(fakeArea()).read()).toEqual(DEFAULT_SETTINGS);
  });
});

describe("mergeSettingsPatch", () => {
  it("never leaves capture running with no case", () => {
    const r = mergeSettingsPatch({ ...DEFAULT_SETTINGS, caseId: "CASE-A", running: true }, { caseId: "  " });
    expect(r.stoppedForNoCase).toBe(true);
    expect(r.settings.running).toBe(false);
  });

  it("repairs a stored running-without-case value", () => {
    const r = mergeSettingsPatch({ ...DEFAULT_SETTINGS, running: true }, {});
    expect(r).toMatchObject({ stoppedForNoCase: true, settings: { running: false } });
  });

  it("leaves a valid running state alone", () => {
    const r = mergeSettingsPatch({ ...DEFAULT_SETTINGS, caseId: "CASE-A", running: true }, { serviceToken: "t" });
    expect(r).toMatchObject({ stoppedForNoCase: false, settings: { running: true, serviceToken: "t" } });
  });
});

describe("sanitizeSettingsPatch", () => {
  it("normalises like the popup form and drops unknown keys", () => {
    expect(
      sanitizeSettingsPatch({
        caseId: " CASE-A ", companionUrl: "http://h:1/ ", serviceToken: " t ", intervalSeconds: "5", running: true, evil: 1,
      }),
    ).toEqual({ caseId: "CASE-A", companionUrl: "http://h:1", serviceToken: "t", intervalSeconds: 30, running: true });
  });

  it("keeps only the fields named", () => {
    expect(sanitizeSettingsPatch({ running: false })).toEqual({ running: false });
  });

  it.each([null, "x", [], { running: "yes" }, { caseId: 5 }, { intervalSeconds: "abc" }, { intervalSeconds: 0 }])(
    "rejects %j",
    (raw) => {
      expect(sanitizeSettingsPatch(raw)).toBeUndefined();
    },
  );
});

describe("sanitizeSettingsExpectation", () => {
  it("keeps string conditions on the case and connection only", () => {
    expect(sanitizeSettingsExpectation({ caseId: "A", companionUrl: "u", serviceToken: "", running: true })).toEqual({
      caseId: "A", companionUrl: "u", serviceToken: "",
    });
  });
  it("passes through an absent condition", () => {
    expect(sanitizeSettingsExpectation(undefined)).toBeUndefined();
  });
  it.each([null, "A", [], {}, { caseId: 1 }])("refuses %j", (raw) => {
    expect(sanitizeSettingsExpectation(raw)).toBeNull();
  });
});

describe("SettingsReconciler — timer and icon follow the stored value", () => {
  it("applies passes in order using the settings current when each runs", async () => {
    const area = fakeArea({ caseId: "CASE-A", running: false });
    const writer = new SettingsWriter(area);
    const applied: Array<[boolean, boolean]> = [];
    const reconciler = new SettingsReconciler(
      () => writer.read(),
      async (s, flip) => { await new Promise((r) => setTimeout(r, 2)); applied.push([s.running, flip]); },
    );
    await writer.update({ running: true });
    const first = reconciler.request(true);
    await writer.update({ running: false });
    const second = reconciler.request(true);
    await Promise.all([first, second]);
    expect(applied.at(-1)).toEqual([false, true]);
  });

  it("a failing pass is reported and does not stop the next", async () => {
    const errors: unknown[] = [];
    let calls = 0;
    const reconciler = new SettingsReconciler(
      async () => DEFAULT_SETTINGS,
      async () => { calls += 1; if (calls === 1) throw new Error("alarm"); },
      (e) => errors.push(e),
    );
    await reconciler.request();
    await reconciler.request();
    expect(calls).toBe(2);
    expect(errors).toHaveLength(1);
  });
});

describe("settingsChangeNeedsReconcile", () => {
  it("reconciles on a running change and flags it", () => {
    expect(
      settingsChangeNeedsReconcile({ oldValue: { running: false }, newValue: { running: true } }),
    ).toEqual({ reconcile: true, runningChanged: true });
  });

  it("reconciles on an interval change without flipping the badge", () => {
    expect(
      settingsChangeNeedsReconcile({ oldValue: { intervalSeconds: 30 }, newValue: { intervalSeconds: 60 } }),
    ).toEqual({ reconcile: true, runningChanged: false });
  });

  it("ignores a token-only change", () => {
    expect(
      settingsChangeNeedsReconcile({ oldValue: { serviceToken: "a" }, newValue: { serviceToken: "b" } }),
    ).toEqual({ reconcile: false, runningChanged: false });
  });

  it("ignores changes to other keys", () => {
    expect(settingsChangeNeedsReconcile(undefined)).toEqual({ reconcile: false, runningChanged: false });
  });
});

describe("SerialQueue", () => {
  it("runs jobs one at a time in call order", async () => {
    const q = new SerialQueue();
    const log: string[] = [];
    const job = (name: string, ms: number) => q.run(async () => {
      log.push(`start ${name}`);
      await new Promise((r) => setTimeout(r, ms));
      log.push(`end ${name}`);
    });
    await Promise.all([job("a", 5), job("b", 1)]);
    expect(log).toEqual(["start a", "end a", "start b", "end b"]);
  });
});

describe("isExtensionPageSender", () => {
  const base = "chrome-extension://abc/";
  it("accepts the popup and options pages", () => {
    expect(isExtensionPageSender("chrome-extension://abc/options.html", base)).toBe(true);
  });
  it("refuses a content script on a web page", () => {
    expect(isExtensionPageSender("https://console.example/", base)).toBe(false);
    expect(isExtensionPageSender(undefined, base)).toBe(false);
  });
});

describe("requestSettingsUpdate", () => {
  it("returns the worker's answer", async () => {
    const answer = { ok: true, settings: DEFAULT_SETTINGS, applied: true, stoppedForNoCase: false };
    const sent: unknown[] = [];
    const r = await requestSettingsUpdate(async (m) => { sent.push(m); return answer; }, { running: false }, { caseId: "CASE-A" });
    expect(r).toEqual(answer);
    expect(sent).toEqual([{ kind: "update_settings", patch: { running: false }, expect: { caseId: "CASE-A" } }]);
  });

  it("turns a rejected message into a reportable failure", async () => {
    const r = await requestSettingsUpdate(async () => { throw new Error("port closed"); }, {});
    expect(r).toEqual({ ok: false, error: "port closed" });
  });

  it("treats a missing answer as a failure, not a save", async () => {
    const r = await requestSettingsUpdate(async () => undefined, {});
    expect(r.ok).toBe(false);
  });
});
