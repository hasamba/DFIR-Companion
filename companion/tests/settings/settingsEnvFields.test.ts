import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";

import { validateEnvUpdates } from "../../src/settings/envManager.js";

/**
 * The Settings modal and POST /settings/env share an implicit contract: every field the modal lets
 * the analyst TYPE INTO must be on the server's writable allowlist. When the allowlist landed (#240)
 * it was never reconciled against the 250-odd `env-*` fields the modal renders, so 49 of them were
 * rejected — and because Save posted every field at once, the 400 killed the whole save. Changing a
 * single Timesketch URL failed with a wall of unrelated key names.
 *
 * These tests pin both halves of the contract so adding a Settings field without allowlisting its
 * key (or allowlisting a key that must stay read-only) fails here instead of in the analyst's face.
 */

const FIELD_TAG = /<(input|select|textarea)\b[^>]*\bid="env-([A-Za-z0-9_]+)"[^>]*>/g;

interface EnvField {
  key: string;
  readOnly: boolean;
}

async function envFields(): Promise<EnvField[]> {
  const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
  const out: EnvField[] = [];
  for (const m of html.matchAll(FIELD_TAG)) {
    out.push({ key: m[2], readOnly: /\breadonly\b/i.test(m[0]) || /\bdisabled\b/i.test(m[0]) });
  }
  return out;
}

describe("Settings modal ⇄ POST /settings/env allowlist", () => {
  it("renders every env-* field the modal reads", async () => {
    const fields = await envFields();
    // Sanity: the regex actually matched the modal, so an empty result can't pass the tests below.
    expect(fields.length).toBeGreaterThan(200);
    expect(fields.map((f) => f.key)).toContain("DFIR_TIMESKETCH_URL");
  });

  it("accepts every editable field — no analyst can type into a key the server rejects", async () => {
    const editable = (await envFields()).filter((f) => !f.readOnly);
    const updates = Object.fromEntries(editable.map((f) => [f.key, "x"]));
    expect(validateEnvUpdates(updates)).toEqual([]);
  });

  it("marks every non-writable field read-only rather than letting Save fail on it", async () => {
    const readOnly = (await envFields()).filter((f) => f.readOnly).map((f) => f.key);
    // The read-only fields exist precisely BECAUSE the server refuses them (bind host, port, cases
    // root, log dir, anonymize default) — they stay visible so the analyst can read the live value.
    const stillAccepted = readOnly.filter((k) => validateEnvUpdates({ [k]: "x" }).length === 0);
    expect(stillAccepted).toEqual([]);
  });
});

describe("saveSettings()", () => {
  it("posts only the keys the analyst actually changed", async () => {
    // saveSettings moved to js/dashboard-env-settings.js (#415 tier 3) and openSettingsModal to a
    // different module again, so the old end marker is not in the same file. Sliced from the
    // function to the initializer that follows it, both of which are in this module.
    const html = await readFile(
      new URL("../../../public/js/dashboard-env-settings.js", import.meta.url),
      "utf8",
    );
    const fn = html.slice(
      html.indexOf("async function saveSettings()"),
      html.indexOf("function initEnvSettings()"),
    );
    expect(fn, "the saveSettings slice is empty — every assertion below would be vacuous").not.toBe("");
    // The diff against the loaded baseline must happen BEFORE the POST, not after it.
    const diffAt = fn.indexOf("loadedEnvValues[key]");
    const postAt = fn.indexOf('fetch("/settings/env"');
    expect(diffAt).toBeGreaterThan(-1);
    expect(postAt).toBeGreaterThan(diffAt);
    // Read-only fields are skipped outright — they can never be part of an update.
    expect(fn).toMatch(/readOnly|disabled/);
  });

  it("keeps a save error on screen instead of clearing it after a few seconds", async () => {
    // saveSettings moved to js/dashboard-env-settings.js (#415 tier 3) and openSettingsModal to a
    // different module again, so the old end marker is not in the same file. Sliced from the
    // function to the initializer that follows it, both of which are in this module.
    const html = await readFile(
      new URL("../../../public/js/dashboard-env-settings.js", import.meta.url),
      "utf8",
    );
    const fn = html.slice(
      html.indexOf("async function saveSettings()"),
      html.indexOf("function initEnvSettings()"),
    );
    expect(fn, "the saveSettings slice is empty — every assertion below would be vacuous").not.toBe("");
    expect(fn).toMatch(/if \(ok\)\s*setTimeout\(/);
  });
});
