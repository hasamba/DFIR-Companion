import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

// U2: Watson's own provider, key and base URL sit next to the Watson model in Settings → AI. The key
// is a password field, and the provider offers the same choices as the Velociraptor provider.

// Windows checkouts use CRLF; the source-text checks below expect LF.
const lf = (text: string) => text.replace(/\r\n/g, "\n");
const html = async () =>
  lf(await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8"));

function selectOptions(page: string, id: string): string[] {
  const start = page.indexOf(`<select id="${id}"`);
  const body = page.slice(start, page.indexOf("</select>", start));
  return [...body.matchAll(/<option value="([^"]*)">([^<]*)<\/option>/g)].map((m) => `${m[1]}|${m[2]}`);
}

describe("Watson provider settings fields", () => {
  it("offers the Velociraptor provider choices, with a blank first option for the synthesis provider", async () => {
    const page = await html();
    const watson = selectOptions(page, "env-DFIR_AI_WATSON_PROVIDER");
    const velo = selectOptions(page, "env-DFIR_AI_VELO_PROVIDER");
    expect(watson[0]).toBe("|— blank: synthesis provider —");
    expect(watson.slice(1)).toEqual(velo.slice(1));
  });

  it("places the three fields after the Watson model and hides the key", async () => {
    const page = await html();
    const model = page.indexOf('id="env-DFIR_AI_WATSON_MODEL"');
    const ids = ["PROVIDER", "KEY", "BASE_URL"].map((s) => page.indexOf(`id="env-DFIR_AI_WATSON_${s}"`));
    for (const at of ids) expect(at).toBeGreaterThan(model);
    const keyTag = page.slice(ids[1], page.indexOf(">", ids[1]));
    expect(keyTag).toContain('type="password"');
    expect(keyTag).toContain('autocomplete="new-password"');
  });

  it("names the Watson role in the key-move notice", async () => {
    const js = lf(
      await readFile(new URL("../../../public/js/dashboard-env-settings.js", import.meta.url), "utf8"),
    );
    expect(js).toMatch(/\n\s+watson: "Watson",\n/);
  });

  it("documents the three settings in .env.example", async () => {
    const example = lf(await readFile(new URL("../../.env.example", import.meta.url), "utf8"));
    for (const s of ["PROVIDER", "KEY", "BASE_URL"]) {
      expect(example).toMatch(new RegExp(`^# DFIR_AI_WATSON_${s}=$`, "m"));
    }
  });
});
