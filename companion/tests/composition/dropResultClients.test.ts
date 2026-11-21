import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { csvCells, severalPcs } from "../../src/composition/dropResultClients.js";

// #2805: is a dropped Velociraptor result file one PC's results or several PCs'? Synthetic data only.

async function put(name: string, text: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "dfir-clients-"));
  const path = join(dir, name);
  await writeFile(path, text);
  return path;
}

const A = "C.0000000000000001";
const B = "C.0000000000000002";

describe("several PCs in one result file (#2805)", () => {
  it("JSONL: two client ids, even when the second appears only far past the head", async () => {
    const one = Array.from({ length: 30000 }, (_, i) => JSON.stringify({ ClientId: A, Pid: i })).join("\n");
    const path = await put("x.json", `${one}\n${JSON.stringify({ ClientId: B, Pid: 1 })}\n`);
    expect(await severalPcs(path, "x.json")).toBe(true);
    expect(await severalPcs(await put("y.json", `${one}\n`), "y.json")).toBe(false);
  });

  it("CSV: reads the ClientId column, including the last line without a newline", async () => {
    const head = "Name,ClientId,Cmd\n";
    const rows = Array.from({ length: 20000 }, (_, i) => `p${i}.exe,${A},"a, b"`).join("\n");
    expect(await severalPcs(await put("a.csv", `${head}${rows}\nq.exe,${B},x`), "a.csv")).toBe(true);
    expect(await severalPcs(await put("b.csv", `${head}${rows}\n`), "b.csv")).toBe(false);
  });

  it("CSV without a ClientId column, or values that are not client ids, is one PC", async () => {
    expect(await severalPcs(await put("c.csv", `Name,Pid\na,1\nb,2\n`), "c.csv")).toBe(false);
    expect(await severalPcs(await put("d.csv", `ClientId,Pid\nfoo,1\nbar,2\n`), "d.csv")).toBe(false);
  });

  it("a hunt-wide `All <Artifact>` file is several PCs by name", async () => {
    expect(await severalPcs(await put("All X.json", "{}\n"), "All X.json")).toBe(true);
  });

  it("splits quoted CSV cells", () => {
    expect(csvCells(`a,"b, c","d ""e"""\r`)).toEqual(["a", "b, c", 'd "e"']);
  });
});
