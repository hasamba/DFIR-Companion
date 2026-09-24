// The synthesis strip's evidence mix (#4) names each selection class the model saw. Synthesis also
// records how many freshly promoted rows it showed (#1586), and that count must lead the line —
// "3 promoted · 24 anchors …" — or the analyst cannot see their promotion reached the model.
import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";

async function labels(): Promise<Record<string, string>> {
  const src = await readFile(new URL("../../../public/js/dashboard-narrative.js", import.meta.url), "utf8");
  const m = src.match(/const LABELS = (\{[\s\S]*?\});/);
  expect(m, "LABELS map not found in dashboard-narrative.js").not.toBeNull();
  // The map is flat `key: "label",` pairs, so read them in source order rather than evaluating it.
  return Object.fromEntries(Array.from(m![1].matchAll(/(\w+):\s*"([^"]*)"/g), (p) => [p[1], p[2]]));
}

// The same join the strip performs, over the map the file really ships.
const mix = (map: Record<string, string>, sc: Record<string, number>): string =>
  Object.keys(map)
    .filter((k) => (sc[k] || 0) > 0)
    .map((k) => `${sc[k]} ${map[k]}`)
    .join(" · ");

describe("evidence mix labels (#1586)", () => {
  it("lists promoted first", async () => {
    const map = await labels();
    expect(Object.keys(map)[0]).toBe("promoted");
    expect(map.promoted).toBe("promoted");
  });

  it("reads 'N promoted' ahead of the anchors", async () => {
    expect(mix(await labels(), { anchor: 24, promoted: 3, rare: 8 })).toBe(
      "3 promoted · 24 anchors · 8 rare",
    );
  });

  it("leaves promoted out when synthesis saw none", async () => {
    expect(mix(await labels(), { anchor: 24, promoted: 0 })).toBe("24 anchors");
  });
});
