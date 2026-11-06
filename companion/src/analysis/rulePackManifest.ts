// The detection-rule pack manifest (#2349): what companion/scripts/buildRulePack.mjs writes next to
// the rules file in every `rules-*` release, and what the companion checks before it will show,
// let alone install, a pack. PURE: no I/O.
//
// A manifest is untrusted input — downloaded, or handed over as a file — so it is parsed with a
// strict schema, and every file it names is checked against its SHA-256 here, not trusted.
//
// WHICH PACKS THIS APP CAN USE. The pack's minimum app version is the companion version on master
// when the pack was built. So:
//   - minAppVersion > running app  → the pack needs a newer app: refused, with a message saying so;
//   - minAppVersion = running app  → a pack published after this app's release: usable;
//   - minAppVersion < running app  → built before this app was released, and this app's bundled
//     rules already contain it: "superseded". It is never offered, and an installed one stops being
//     used after an app upgrade (the bundled rules take over), so upgrading never runs older rules.

import { z } from "zod";
import { compareVersions } from "./updateCheck.js";
import { sha256Hex } from "./githubReleaseDownload.js";

export const RULE_PACK_KIND = "dfir-companion-rule-pack";
export const RULE_PACK_RULES_ASSET = "tags.yaml";
export const RULE_PACK_MANIFEST_ASSET = "rule-pack-manifest.json";
/** Caps for a downloaded or uploaded pack: the rules file and the manifest. */
export const RULE_PACK_MAX_RULES_BYTES = 4 * 1024 * 1024;
export const RULE_PACK_MAX_MANIFEST_BYTES = 256 * 1024;

const TAG = /^rules-(\d{4})\.(\d{2})\.(\d{2})(?:\.(\d{1,4}))?$/;
const HEX64 = /^[0-9a-f]{64}$/;

export const isRulePackTag = (tag: string): boolean => TAG.test(tag);

/** Order two pack versions (`rules-YYYY.MM.DD[.N]`; no suffix counts as .1). Unparsable sorts first. */
export function comparePackVersions(a: string, b: string): -1 | 0 | 1 {
  const key = (v: string): number[] => {
    const m = TAG.exec(v);
    return m ? [+m[1], +m[2], +m[3], m[4] ? +m[4] : 1] : [-1];
  };
  const ka = key(a);
  const kb = key(b);
  for (let i = 0; i < Math.max(ka.length, kb.length); i++) {
    const x = ka[i] ?? 0;
    const y = kb[i] ?? 0;
    if (x !== y) return x > y ? 1 : -1;
  }
  return 0;
}

const manifestSchema = z.object({
  schema: z.literal(1),
  kind: z.literal(RULE_PACK_KIND),
  version: z.string().regex(TAG, "version must look like rules-YYYY.MM.DD"),
  minAppVersion: z
    .string()
    .regex(/^\d+\.\d+\.\d+[0-9A-Za-z.+-]*$/)
    .max(40),
  createdAt: z.string().max(40),
  commit: z
    .string()
    .regex(/^[0-9a-f]{7,40}$/)
    .optional(),
  ruleCount: z.number().int().nonnegative(),
  sources: z
    .array(
      z.object({
        name: z.string().min(1).max(120),
        commit: z.string().regex(/^[0-9a-f]{40}$/),
        date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
      }),
    )
    .max(50),
  files: z
    .array(
      z.object({
        name: z.string().min(1).max(100),
        sha256: z.string().regex(HEX64),
        bytes: z.number().int(),
      }),
    )
    .min(1)
    .max(10),
});

export type RulePackManifest = z.infer<typeof manifestSchema>;

/** Parse and validate a manifest's text, or throw a sentence saying what is wrong. */
export function parseRulePackManifest(text: string): RulePackManifest {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new Error("the rule pack manifest is not valid JSON");
  }
  const parsed = manifestSchema.safeParse(doc);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    throw new Error(
      `the rule pack manifest is not valid: ${first.path.join(".") || "root"} — ${first.message}`,
    );
  }
  return parsed.data;
}

/** Throw unless the rules file is listed in the manifest with exactly these bytes' SHA-256. */
export function verifyRulesAgainstManifest(manifest: RulePackManifest, rulesText: string): void {
  const entry = manifest.files.find((f) => f.name === RULE_PACK_RULES_ASSET);
  if (!entry) throw new Error(`the rule pack manifest lists no ${RULE_PACK_RULES_ASSET}`);
  if (sha256Hex(rulesText) !== entry.sha256)
    throw new Error(
      `${RULE_PACK_RULES_ASSET} does not match the SHA-256 in the rule pack manifest; nothing was installed`,
    );
}

export type PackFit = "ok" | "needs-newer-app" | "superseded";

/** Whether this app can use the pack (see the header). An unknown app version fits nothing. */
export function packFit(minAppVersion: string, appVersion: string): PackFit {
  if (!appVersion || appVersion === "unknown") return "needs-newer-app";
  const c = compareVersions(minAppVersion, appVersion);
  return c === 1 ? "needs-newer-app" : c === 0 ? "ok" : "superseded";
}

export function needsNewerAppMessage(version: string, minAppVersion: string, appVersion: string): string {
  return `rule pack ${version} needs DFIR Companion ${minAppVersion} or newer (this is ${appVersion}); update the app to use it`;
}
