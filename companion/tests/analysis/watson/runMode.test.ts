import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AiControlStore } from "../../../src/analysis/aiControl.js";
import {
  isWatsonRunMode,
  watsonModeDetail,
  watsonModePatch,
  watsonRunMode,
} from "../../../src/analysis/ai/watson/runMode.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

describe("Watson run mode", () => {
  it("defaults to approve, and reads junk as approve", () => {
    expect(watsonRunMode({})).toBe("approve");
    expect(watsonRunMode(undefined)).toBe("approve");
    expect(watsonRunMode({ watsonRunMode: "AUTO" })).toBe("approve");
    expect(watsonRunMode({ watsonRunMode: 7 })).toBe("approve");
    expect(watsonRunMode({ watsonRunMode: "auto" })).toBe("auto");
    expect(isWatsonRunMode("auto")).toBe(true);
    expect(isWatsonRunMode("fleet")).toBe(false);
  });

  it("auto records who and when; approve clears both", () => {
    const now = new Date("2026-11-14T10:00:00Z");
    expect(watsonModePatch("auto", { id: "u1", name: "Alice" }, now)).toEqual({
      watsonRunMode: "auto",
      watsonAutoSince: "2026-11-14T10:00:00.000Z",
      watsonAutoBy: { id: "u1", name: "Alice" },
    });
    expect(watsonModePatch("auto", { name: "analyst" }, now).watsonAutoBy).toEqual({ name: "analyst" });
    expect(watsonModePatch("approve", { name: "Alice" })).toEqual({
      watsonRunMode: "approve",
      watsonAutoSince: undefined,
      watsonAutoBy: undefined,
    });
    expect(watsonModeDetail("auto")).toBe("Switched Watson to Auto");
    expect(watsonModeDetail("approve")).toBe("Switched Watson to Approve");
  });

  it("an ai-control file written before the field existed loads as approve", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-runmode-")));
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await writeFile(
      join(store.stateDir("c1"), "ai-control.json"),
      JSON.stringify({ enabled: true, lastAnalyzedSeq: 3 }),
    );
    const control = await new AiControlStore(store).load("c1");
    expect(watsonRunMode(control)).toBe("approve");
    expect(control.lastAnalyzedSeq).toBe(3);
  });

  it("the mode and its provenance survive a reload and change on each switch", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-runmode-")));
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const controls = new AiControlStore(store);
    await controls.save("c1", { enabled: true, lastAnalyzedSeq: 0 });
    const on = { ...(await controls.load("c1")), ...watsonModePatch("auto", { id: "u1", name: "Alice" }) };
    await controls.save("c1", on);
    const reloaded = await controls.load("c1");
    expect(reloaded).toMatchObject({ watsonRunMode: "auto", watsonAutoBy: { id: "u1", name: "Alice" } });
    expect(typeof reloaded.watsonAutoSince).toBe("string");
    await controls.save("c1", { ...reloaded, ...watsonModePatch("approve", { name: "Bob" }) });
    const off = await controls.load("c1");
    expect(off.watsonRunMode).toBe("approve");
    expect(off).not.toHaveProperty("watsonAutoSince");
    expect(off).not.toHaveProperty("watsonAutoBy");
  });
});
