// The automatic tagger's labels for the rows of one timeline page (#2059). The tag list the dashboard
// holds carries analyst tags only — on an auto-tagged case the tagger's tags are one per matched event
// and label, ~10 MB, and the dashboard re-read all of them on every tag change. Instead each page the
// dashboard loads (forensic timeline, super-timeline) carries the tagger tags of its own rows, so the
// cost follows the page and never the case.
//
// A tag on an event correlation later folded into another (#1715) shows on the survivor too, exactly
// as the list's `resolvedTargetId` made it: the absorbed ids whose lineage names a row are looked up
// with the row ids, and each tag lands on every row among its own id and the id it resolves to.

import type { Tag } from "./tags.js";
import { eventTargetIds, resolverFromAliases, type EventAliasSource } from "./eventAliasLookup.js";

/** A tagger tag as a page carries it: the row id is the key, the target type is always "event". */
export interface RowTaggerTag {
  id: string;
  label: string;
  author: string;
}

/** Row id -> its tagger tags, for the rows that have any. */
export type RowTaggerTags = Record<string, RowTaggerTag[]>;

/** The most row ids one lookup answers — a page is far smaller; this bounds a client's refresh. */
export const MAX_TAGGER_ROW_IDS = 5000;

interface TaggerTagReader {
  taggerTagsFor(caseId: string, targetIds: readonly string[]): Promise<Tag[]>;
}

/** The absorbed ids whose lineage ends on one of these rows. */
function absorbedInto(
  aliases: Readonly<Record<string, string>> | undefined,
  rows: ReadonlySet<string>,
): string[] {
  if (!aliases) return [];
  return Object.keys(aliases).filter((from) => !rows.has(from) && rows.has(aliases[from]));
}

/** The tagger tags of `rowIds`, keyed by row id; empty when the case has no tags store. */
export async function taggerTagsForRows(
  tags: TaggerTagReader | undefined,
  aliasSource: EventAliasSource | undefined,
  caseId: string,
  rowIds: readonly string[],
): Promise<RowTaggerTags> {
  const rows = new Set(rowIds.filter((id) => typeof id === "string" && id));
  if (!tags || rows.size === 0) return {};
  const aliases = aliasSource ? await aliasSource.loadEventAliases(caseId) : undefined;
  const found = await tags.taggerTagsFor(caseId, [...rows, ...absorbedInto(aliases, rows)]);
  const resolve = aliasSource
    ? await resolverFromAliases(aliasSource, caseId, aliases, eventTargetIds(found))
    : (id: string) => id;
  const out: RowTaggerTags = {};
  for (const t of found) {
    const entry: RowTaggerTag = { id: t.id, label: t.label, author: t.author };
    for (const key of new Set([t.targetId, resolve(t.targetId)])) {
      if (!rows.has(key)) continue;
      // defineProperty, not assignment: a row id spelled "__proto__" must stay data.
      if (!Object.prototype.hasOwnProperty.call(out, key)) {
        Object.defineProperty(out, key, { value: [], enumerable: true, writable: true });
      }
      out[key].push(entry);
    }
  }
  return out;
}
