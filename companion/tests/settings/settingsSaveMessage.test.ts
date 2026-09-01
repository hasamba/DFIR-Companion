import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

/**
 * WHAT THE SAVE MESSAGE CLAIMS HAS TO MATCH WHAT THE SERVER DID.
 *
 * Saving Settings writes .env and then asks POST /settings/reload to load the touched prefixes into
 * the running process. The reply carries two different facts: `rebuilt` (clients swapped out) and
 * `applied` (keys now live in process.env). The message used to branch on `rebuilt` alone, so a key
 * that WAS applied but had no client behind it — DFIR_KEV_ALLOW_INTERNAL_URL (#760), whose route
 * just reads process.env per request — was reported as needing a restart it did not need.
 *
 * Both directions matter. Telling an analyst to restart for a change that is already live teaches
 * them the message is noise; staying quiet about one that is not live leaves them thinking a
 * security toggle took effect when it did not.
 */

interface Element {
  id: string;
  value: string;
  tagName: string;
  type?: string;
  readOnly?: boolean;
  disabled?: boolean;
  checked?: boolean;
  textContent: string;
  style: Record<string, string>;
}

const field = (id: string, value: string): Element => ({
  id,
  value,
  tagName: "INPUT",
  type: "text",
  textContent: "",
  style: {},
});

interface SaveResult {
  message: string;
  reloadedPrefixes: string[];
}

/**
 * Runs the real saveSettings() over one changed env field, with the server's replies scripted.
 * `applied` is what POST /settings/reload reports for every prefix it is asked about.
 */
async function save(
  envFields: Element[],
  reload: { applied: string[]; rebuilt: string[]; live?: boolean },
): Promise<SaveResult> {
  const msg: Element = { id: "settingsSaveMsg", value: "", tagName: "SPAN", textContent: "", style: {} };
  const investigator = field("settingsInvestigator", "");
  const reloadedPrefixes: string[] = [];

  const sandbox = loadDashboardModule<{ saveSettings: () => Promise<boolean> }>(
    "dashboard-env-settings.js",
    [],
    {
      localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
      SECTION_DEFS: [],
      SECTIONS_VIS_KEY: "dfir.sections",
      applySectionsVis: () => {},
      // The success message self-clears on a timer. Never firing it keeps the text readable for
      // the assertion — and a real timer would leak past the test besides.
      setTimeout: () => 0,
      document: {
        getElementById: (id: string) =>
          id === "settingsSaveMsg" ? msg : id === "settingsInvestigator" ? investigator : null,
        querySelectorAll: (selector: string) => (selector === "[id^='env-']" ? envFields : []),
      },
      fetch: async (url: string, init?: { body?: string }) => {
        if (url === "/settings/env") return { ok: true, json: async () => ({ ok: true }) };
        if (url === "/settings/reload") {
          reloadedPrefixes.push(JSON.parse(init?.body ?? "{}").prefix);
          return { ok: true, json: async () => ({ ok: true, ...reload }) };
        }
        return { ok: false, status: 404, json: async () => ({}) };
      },
    },
  );

  await sandbox.saveSettings();
  return { message: msg.textContent, reloadedPrefixes };
}

describe("Settings save message", () => {
  // The #760 regression: applied, nothing to rebuild, and the message said restart anyway.
  it("says a key applied live when the server loaded it and had no client to rebuild", async () => {
    const { message, reloadedPrefixes } = await save([field("env-DFIR_KEV_ALLOW_INTERNAL_URL", "true")], {
      applied: ["DFIR_KEV_ALLOW_INTERNAL_URL"],
      rebuilt: [],
      live: true,
    });

    expect(reloadedPrefixes).toEqual(["DFIR_KEV_"]);
    expect(message).toMatch(/applied live/i);
    expect(message).toMatch(/no restart needed/i);
    // The regression, stated as the thing that must not come back: an instruction to restart.
    expect(message, "the setting IS live — do not send the analyst to restart").not.toMatch(
      /restart the server/i,
    );
  });

  it("still names the rebuilt clients when there are some", async () => {
    const { message } = await save([field("env-DFIR_MISP_URL", "https://misp.example")], {
      applied: ["DFIR_MISP_URL"],
      rebuilt: ["MISP"],
    });

    expect(message).toMatch(/applied live: MISP/);
    expect(message, "nothing was left needing a restart").not.toMatch(/restart the server/i);
  });

  // The honest fallback has to survive: a prefix the server will not reload still needs a restart,
  // and the fix for the case above must not turn that into a false "applied live" either.
  it("still asks for a restart when the key cannot be applied without one", async () => {
    const { message, reloadedPrefixes } = await save([field("env-DFIR_OCR_LANG", "eng")], {
      applied: [],
      rebuilt: [],
    });

    expect(reloadedPrefixes, "DFIR_OCR_ is writable but not reloadable").toEqual([]);
    expect(message).toMatch(/restart the server/i);
  });

  // A save can touch both kinds at once, and saying "applied live" full stop would overclaim.
  it("reports the split when only some of the save went live", async () => {
    const { message } = await save(
      [field("env-DFIR_KEV_ALLOW_INTERNAL_URL", "true"), field("env-DFIR_OCR_LANG", "eng")],
      { applied: ["DFIR_KEV_ALLOW_INTERNAL_URL"], rebuilt: [], live: true },
    );

    expect(message).toMatch(/1 of 2 applied live/);
    expect(message).toMatch(/restart the server for the rest/i);
  });
});

/**
 * "APPLIED" IS NOT "IN EFFECT", AND THE MESSAGE MUST NOT CONFLATE THEM.
 *
 * Every reloadable prefix gets loaded into process.env. Only some of them thereby take hold, and
 * the server is what knows which: it reports `live`. Deciding from `applied` alone told an analyst
 * that an AI model change was running when composition/settingsReload.ts says in as many words that
 * the running pipeline still holds its boot-time config.
 */
describe("Settings save message — applied is not in effect", () => {
  it.each([
    ["env-DFIR_AI_SYNTH_MODEL", "DFIR_AI_SYNTH_MODEL", "DFIR_AI_"],
    ["env-DFIR_VISION_MODEL", "DFIR_VISION_MODEL", "DFIR_VISION_"],
  ])("still asks for a restart after %s, which reloads but does not take hold", async (id, key, prefix) => {
    const { message, reloadedPrefixes } = await save([field(id, "some-model")], {
      applied: [key], // the env DID change
      rebuilt: [], // nothing was swapped out
      live: false, // and the running pipeline has not moved
    });

    expect(reloadedPrefixes).toEqual([prefix]);
    expect(message, "the model change is not running yet").toMatch(/restart the server/i);
    expect(message).not.toMatch(/no restart needed/i);
  });

  // A prefix the server has not classified at all must not be assumed live either.
  it("treats a missing live flag as not in effect", async () => {
    const { message } = await save([field("env-DFIR_AI_SYNTH_MODEL", "m")], {
      applied: ["DFIR_AI_SYNTH_MODEL"],
      rebuilt: [],
    });

    expect(message).toMatch(/restart the server/i);
  });

  // Mixed save: one key genuinely live, one only applied. The count must reflect the live one only.
  it("counts only the keys that are actually in effect", async () => {
    const msg = { id: "settingsSaveMsg", value: "", tagName: "SPAN", textContent: "", style: {} };
    const investigator = field("settingsInvestigator", "");
    const fields = [
      field("env-DFIR_KEV_ALLOW_INTERNAL_URL", "true"),
      field("env-DFIR_AI_SYNTH_MODEL", "some-model"),
    ];

    const sandbox = loadDashboardModule<{ saveSettings: () => Promise<boolean> }>(
      "dashboard-env-settings.js",
      [],
      {
        localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
        SECTION_DEFS: [],
        SECTIONS_VIS_KEY: "dfir.sections",
        applySectionsVis: () => {},
        setTimeout: () => 0,
        document: {
          getElementById: (id: string) =>
            id === "settingsSaveMsg" ? msg : id === "settingsInvestigator" ? investigator : null,
          querySelectorAll: (selector: string) => (selector === "[id^='env-']" ? fields : []),
        },
        // Each prefix answers for itself: DFIR_KEV_ is live, DFIR_AI_ is applied only.
        fetch: async (url: string, init?: { body?: string }) => {
          if (url === "/settings/env") return { ok: true, json: async () => ({ ok: true }) };
          if (url === "/settings/reload") {
            const prefix = JSON.parse(init?.body ?? "{}").prefix as string;
            return {
              ok: true,
              json: async () =>
                prefix === "DFIR_KEV_"
                  ? { ok: true, applied: ["DFIR_KEV_ALLOW_INTERNAL_URL"], rebuilt: [], live: true }
                  : { ok: true, applied: ["DFIR_AI_SYNTH_MODEL"], rebuilt: [], live: false },
            };
          }
          return { ok: false, status: 404, json: async () => ({}) };
        },
      },
    );

    await sandbox.saveSettings();
    expect(msg.textContent).toMatch(/1 of 2 applied live/);
    expect(msg.textContent).toMatch(/restart the server for the rest/i);
  });
});
