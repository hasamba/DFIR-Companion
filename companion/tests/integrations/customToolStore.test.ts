import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CustomToolStore,
  customToolToConfig,
  normalizeExt,
  slugifyToolName,
  type CustomTool,
} from "../../src/integrations/tools/customToolStore.js";

async function store() {
  const root = await mkdtemp(join(tmpdir(), "dfir-customtool-"));
  return new CustomToolStore(join(root, "tools", "custom-tools.json"));
}

describe("normalizeExt / slugifyToolName", () => {
  it("normalizes extensions to a single lowercase dotted token", () => {
    expect(normalizeExt("EVTX")).toBe(".evtx");
    expect(normalizeExt(".PCAP")).toBe(".pcap");
    expect(normalizeExt("  .Db ")).toBe(".db");
    expect(normalizeExt("")).toBe("");
    expect(normalizeExt("../evil")).toBe(".evil"); // strips slashes/dots → "evil" → ".evil"
  });
  it("slugifies a tool name to a stable id", () => {
    expect(slugifyToolName("My Cool Tool")).toBe("custom-my-cool-tool");
    expect(slugifyToolName("evtx2json!!")).toBe("custom-evtx2json");
  });
});

describe("customToolToConfig", () => {
  it("uses stdout mode when the command has no <output>", () => {
    const t: CustomTool = { id: "custom-x", name: "X", binary: "x", runArgs: "-r <target>", extensions: [".db"], autoRun: false, timeoutMs: 1000, maxOutputBytes: 100 };
    const cfg = customToolToConfig(t);
    expect(cfg.importKind).toBe("auto");
    expect(cfg.outputMode).toBe("stdout");
    expect(cfg.outputFile).toBeUndefined();
  });
  it("uses file mode when the command writes <output>", () => {
    const t: CustomTool = { id: "custom-y", name: "Y", binary: "y", runArgs: "-r <target> -o <output>", extensions: [".db"], autoRun: true, timeoutMs: 1000, maxOutputBytes: 100 };
    const cfg = customToolToConfig(t);
    expect(cfg.outputMode).toBe("file");
    expect(cfg.outputFile).toBe("output.dat");
    expect(cfg.autoRun).toBe(true);
  });
});

describe("CustomToolStore", () => {
  it("adds, loads, and normalizes a custom tool", async () => {
    const s = await store();
    const t = await s.add({ name: "EVTX2JSON", binary: "C:\\tools\\evtx2json.exe", runArgs: "<target> -o <output>", extensions: "evtx, .EVT xyz", autoRun: true });
    expect(t.id).toBe("custom-evtx2json");
    expect(t.extensions).toEqual([".evtx", ".evt", ".xyz"]);
    expect(t.autoRun).toBe(true);
    const list = await s.load();
    expect(list).toHaveLength(1);
    expect(list[0].name).toBe("EVTX2JSON");
  });

  it("requires a name and a binary", async () => {
    const s = await store();
    await expect(s.add({ name: "", binary: "x" })).rejects.toThrow(/name is required/i);
    await expect(s.add({ name: "x", binary: "" })).rejects.toThrow(/binary path is required/i);
  });

  it("re-adding the same name replaces (no duplicate)", async () => {
    const s = await store();
    await s.add({ name: "Tool A", binary: "a1" });
    await s.add({ name: "Tool A", binary: "a2" });
    const list = await s.load();
    expect(list).toHaveLength(1);
    expect(list[0].binary).toBe("a2");
  });

  it("updates by id (keeps the id even if the name changes)", async () => {
    const s = await store();
    const t = await s.add({ name: "Orig", binary: "b" });
    const upd = await s.update(t.id, { name: "Renamed", autoRun: true });
    expect(upd?.id).toBe(t.id);
    expect(upd?.name).toBe("Renamed");
    expect(upd?.autoRun).toBe(true);
    expect(await s.update("nope", { name: "x" })).toBeNull();
  });

  it("removes a tool", async () => {
    const s = await store();
    const t = await s.add({ name: "Del", binary: "b" });
    expect(await s.remove(t.id)).toBe(true);
    expect(await s.remove(t.id)).toBe(false);
    expect(await s.load()).toHaveLength(0);
  });
});
