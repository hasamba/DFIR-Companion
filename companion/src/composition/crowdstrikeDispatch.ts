// The `crowdstrike` import kind as a file-level router (#2592 Part 3). A Falcon export can carry
// Falcon's own rows (sensor events, alerts) AND third-party logs Next-Gen SIEM stored for it (Okta,
// Google Cloud, Microsoft 365, …). analysis/crowdstrikeUnwrap.ts splits the file row by row; this sends
// the Falcon rows to the Falcon importer and each third-party group to the importer for its real tool.
//
// Everything runs inside the caller's one import (same lock, same baseline), so the route's settle step
// — dual-write, tagger, demote, the undo checkpoint — covers every row the upload added. A plain Falcon
// file (no wrapped rows) goes to the Falcon importer with its original text, unchanged.

import { splitCrowdstrikeFile } from "../analysis/crowdstrikeUnwrap.js";
import type { ImportBase } from "../routes/context.js";

export interface CrowdstrikeDispatchDeps {
  /** The Falcon importer. For a subset rebuilt from the upload, `subset` names the uploaded text and
   * each row's index in it, so hashes and evidence locators point at the artifact itself. */
  importFalcon(
    text: string,
    base: ImportBase,
    subset?: { sourceText: string; recordIndexes: readonly number[] },
  ): Promise<unknown>;
  /** The unified dispatcher, for the third-party importers (never called with `crowdstrike`). */
  dispatch(kind: string, text: string, base: ImportBase): Promise<unknown>;
}

const ndjson = (rows: readonly unknown[]): string => rows.map((r) => JSON.stringify(r)).join("\n");

export async function dispatchCrowdstrike(
  text: string,
  base: ImportBase,
  deps: CrowdstrikeDispatchDeps,
): Promise<unknown> {
  const split = splitCrowdstrikeFile(text);
  if (split.wrapped === 0) return deps.importFalcon(text, base);
  let last: unknown;
  if (split.falcon.length > 0)
    last = await deps.importFalcon(ndjson(split.falcon), base, {
      sourceText: text,
      recordIndexes: split.falconIndexes,
    });
  let n = 0;
  for (const [kind, rows] of split.groups) {
    n++;
    base.debug?.observed(`logscale_wrapped_${kind}`, rows.length);
    // The child gets no debug recorder: this attempt's recorder already logged the `crowdstrike` kind.
    const { debug: _debug, ...childBase } = base;
    last = await deps.dispatch(kind, ndjson(rows), { ...childBase, idPrefix: `${base.idPrefix}w${n}-` });
  }
  return last;
}
