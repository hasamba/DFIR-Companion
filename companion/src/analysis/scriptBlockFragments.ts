// PowerShell script-block (EID 4104) fragment reassembly.
//
// PowerShell logs a script block to Microsoft-Windows-PowerShell/Operational when it is COMPILED.
// When the script text exceeds the event message size limit, Windows does not truncate it — it
// splits the text across several 4104 events that all carry:
//
//   ScriptBlockId  the GUID of the compiled block — identical on every fragment
//   MessageNumber  this fragment's 1-based position
//   MessageTotal   how many fragments the block was split into
//
// and render as "Creating Scriptblock text (2 of 5):". Those N events are ONE compiled script, not
// N scripts. Detection tooling does not know that: DetectRaptor's Evtx rule pack and Hayabusa both
// evaluate each fragment on its own, so one malicious script produced up to N near-identical alerts,
// each showing the analyst a different slice of the text and none showing the whole script.
//
// This module folds the slices back together BEFORE the importers map rows to events. It does NOT
// drop rows and does NOT merge alerts itself. It gives every fragment row of a block the same
// reassembled script text; the importers' existing aggregation key then collapses them naturally,
// because that key is built from the rule verdict plus the event text — which is now identical
// across fragments. Two consequences fall out of doing it this way rather than deleting rows:
//
//   * Record accounting stays honest. Rows in = rows out, so `total`/`dropped` still describe the
//     source file and the merged event's `count` reports how many source records it represents.
//   * Two DIFFERENT rules matching different fragments of one block stay two alerts, because their
//     verdicts differ and the key still separates them — while both now carry the whole script.
//
// Deliberate boundaries:
//   * A single-part block (MessageTotal 1, the overwhelming majority) is never touched.
//   * Fragments are joined by (host, ScriptBlockId). The same GUID seen on two hosts is two blocks.
//   * Fragments are concatenated with NO separator: Windows cuts on a byte budget, so a split can
//     land mid-line or mid-token, and any inserted character would corrupt the reconstructed script.
//   * A block whose fragments are only partly present (the rule matched 2 of 3) is still joined,
//     and the note says "2 of 3" — which parts matched is itself evidence.

import { getCI, getPath, isObject, str } from "./siemImport.js";

type Row = Record<string, unknown>;

/**
 * Ceiling on reassembled script text. Matches velociraptorImport's MESSAGE_CAP: text beyond it is
 * already cut before reaching case state, so a larger cap here would only cost parse-time memory.
 */
export const SCRIPT_BLOCK_TEXT_CAP = 4000;

export interface ScriptBlockFragment {
  id: string; // ScriptBlockId, lowercased
  number: number; // MessageNumber (1-based); 0 when the source did not say
  total: number; // MessageTotal; 0 when the source did not say
  text: string; // this fragment's slice of the script
}

export interface ReassembledScriptBlock {
  text: string; // the fragments concatenated in order, capped
  parts: number; // how many fragments were present
  total: number; // how many the block was split into
  complete: boolean; // every fragment accounted for
}

const GUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i;
// "Creating Scriptblock text (2 of 5):" — the rendered header, and the only place the fragment
// position appears when a source ships the message but not the structured MessageNumber field.
const PART_OF_RE = /\((\d+)\s+of\s+(\d+)\)/i;

function num(v: unknown): number {
  const n = Number(str(v).trim());
  return Number.isFinite(n) && n > 0 ? n : 0;
}

/**
 * Collapse repeats of the same fragment POSITION. One 4104 event that trips several rules is
 * reported once per rule, so the same MessageNumber reaches us several times; concatenating each
 * copy would splice a duplicated slice into the middle of the script and show the analyst code that
 * never ran. A fragment with no stated position is keyed by its text instead, so identical copies
 * still collapse while genuinely different unpositioned slices are all kept.
 *
 * When two renderings of one position disagree, the LONGER text wins: a rule-specific render may
 * have cut the slice short, and the longer copy is the one that loses no evidence.
 */
function dedupeByPosition(frags: readonly ScriptBlockFragment[]): ScriptBlockFragment[] {
  const byPos = new Map<string, ScriptBlockFragment>();
  const order: string[] = [];
  for (const f of frags) {
    const pos = f.number > 0 ? `#${f.number}` : `t:${f.text}`;
    const seen = byPos.get(pos);
    if (!seen) {
      byPos.set(pos, f);
      order.push(pos);
    } else if (f.text.length > seen.text.length) {
      byPos.set(pos, f);
    }
  }
  return order.map((p) => byPos.get(p)!);
}

/**
 * Concatenate the fragments of one script block in MessageNumber order, counting each position
 * once. Fragments with no stated position keep their arrival order, after the numbered ones. Pure.
 */
export function reassembleScriptBlock(frags: readonly ScriptBlockFragment[]): ReassembledScriptBlock {
  const ordered = dedupeByPosition(frags)
    .map((f, i) => ({ f, i }))
    .sort((a, b) => (a.f.number || Infinity) - (b.f.number || Infinity) || a.i - b.i)
    .map(({ f }) => f);
  // Append under a running budget rather than joining everything and slicing afterwards: a block of
  // many large fragments would otherwise allocate the whole uncapped string first, so the cap would
  // bound the RESULT without ever bounding parse-time memory.
  const kept: string[] = [];
  let len = 0;
  let truncated = false;
  for (const f of ordered) {
    if (!f.text) continue;
    const room = SCRIPT_BLOCK_TEXT_CAP - len;
    if (room <= 0) {
      truncated = true;
      break;
    }
    if (f.text.length > room) {
      kept.push(f.text.slice(0, room)); // no separator — see the header note
      truncated = true;
      break;
    }
    kept.push(f.text);
    len += f.text.length;
  }
  const text = truncated ? `${kept.join("")}…` : kept.join("");
  const total = Math.max(0, ...ordered.map((f) => f.total));
  // Counts describe the BLOCK, not how much of it fitted the cap, so a capped block still reports
  // honestly whether every fragment was accounted for.
  const parts = ordered.length;
  return { text, parts, total, complete: total > 0 && parts >= total };
}

/** "3" for a whole block, "2 of 3" when the rule matched only some fragments. */
function partsPhrase(r: ReassembledScriptBlock): string {
  return r.complete ? `${r.total}` : `${r.parts} of ${r.total}`;
}

/** The note stamped onto consolidated text, so the analyst sees the script was joined, not truncated. */
function partsNote(r: ReassembledScriptBlock): string {
  return `\n\n[reassembled from ${partsPhrase(r)} script-block parts]`;
}

/**
 * Group fragments by their block, then hand each multi-fragment group its reassembled text. Takes
 * fragments the caller has ALREADY read, so a row is never inspected twice — reading them here and
 * again while rewriting cost a second full pass over every row of the import.
 */
type ReadFragment = { key: string; frag: ScriptBlockFragment } | null;

function reassembleByBlock(
  read: readonly ReadFragment[],
): Map<string, { full: string; note: string; phrase: string }> {
  const byKey = new Map<string, ScriptBlockFragment[]>();
  for (const r of read) {
    if (!r) continue;
    const list = byKey.get(r.key);
    if (list) list.push(r.frag);
    else byKey.set(r.key, [r.frag]);
  }
  const out = new Map<string, { full: string; note: string; phrase: string }>();
  for (const [key, frags] of byKey) {
    if (frags.length < 2) continue; // nothing to join — leave the row exactly as it was
    const r = reassembleScriptBlock(frags);
    // Several rows, but all of them the SAME fragment (one slice that tripped several rules).
    // There is no second position to join, so the rows keep their own text untouched.
    if (r.parts < 2) continue;
    out.set(key, { full: r.text, note: partsNote(r), phrase: partsPhrase(r) });
  }
  return out;
}

// ───────────────────────────── Velociraptor / DetectRaptor rows ─────────────────────────────

// A 4104 row reaches this importer in one of THREE shapes, all of which must be read:
//
//   1. native parsed evtx      — top-level `System` + `EventData`
//   2. wrapped                 — the same under `Event`
//   3. Velociraptor-decorated  — the same under `_Event`, alongside rendered `Details`/`Title`
//      columns. `Windows.Hayabusa.Rules` emits this, and the row reaches HERE rather than the
//      Hayabusa importer because it carries `_Source`, which the Velociraptor detector claims.
//
// An Elasticsearch round-trip arrives as dotted keys that veloRowNormalize has already un-flattened
// back into shape 1. A row in none of these yields no fragment and is left untouched.
//
// Shape 3 was missed at first and is why this list is spelled out: rowMessage() in velociraptorImport
// already read `_Event`, so the shape was known to the codebase but not to this reader, and a split
// block collected that way stayed one alert per fragment with nothing to signal the miss.
const EVENT_WRAPPERS = ["Event", "_Event"] as const;

function veloEventData(row: Row): Row | null {
  let ed = getCI(row, "EventData");
  for (const w of EVENT_WRAPPERS) {
    if (isObject(ed)) break;
    ed = getPath(row, `${w}.EventData`);
  }
  return isObject(ed) ? ed : null;
}

function veloEventId(row: Row): number {
  const raw =
    getPath(row, "System.EventID.Value") ??
    getPath(row, "Event.System.EventID.Value") ??
    getPath(row, "_Event.System.EventID.Value") ??
    getPath(row, "System.EventID") ??
    getCI(row, "EventID") ??
    getCI(row, "EID");
  if (isObject(raw)) return num(getCI(raw, "Value") ?? getCI(raw, "#text"));
  return num(raw);
}

function veloHost(row: Row): string {
  return (
    str(
      getCI(row, "Computer") ??
        getPath(row, "System.Computer") ??
        getPath(row, "Event.System.Computer") ??
        getPath(row, "_Event.System.Computer") ??
        getCI(row, "Hostname") ??
        getCI(row, "Fqdn"),
    )
      .trim()
      .toLowerCase() || "?"
  );
}

// The rule whose verdict this row carries. Reassembly is scoped by it, because a row is only safe to
// give another row's text if the two cannot then collapse into one alert — and whether they collapse
// depends on a downstream aggregation key this module does not own. A DetectRaptor row keeps its
// title in that key; a `_Event` Hayabusa row does NOT (classify() reads it as generic, so the title
// reaches neither the description nor the key), and there the differing fragment text was the ONLY
// thing holding two rules apart. Handing both rows the same text dropped a verdict out of the case.
// Scoping the group by rule costs a little text — an alert joins the parts ITS rule matched, and the
// "N of M" note discloses the rest — and it cannot lose a verdict, which is the trade forensic
// reporting requires.
function veloRuleIdentity(row: Row): string {
  const det = getCI(row, "Detection");
  const fromDetection = isObject(det) ? str(getCI(det, "Name")) : str(det);
  const title =
    fromDetection ||
    str(getCI(row, "Title") ?? getCI(row, "RuleTitle") ?? getCI(row, "RuleName")) ||
    (isObject(getCI(row, "Rule")) ? str(getCI(getCI(row, "Rule") as Row, "Title")) : "");
  return title.trim().toLowerCase();
}

// Only a genuine multi-part script block qualifies. The event id must be 4104 or unreadable — an
// unreadable id is allowed because ScriptBlockId + MessageTotal > 1 is already specific to 4104,
// and refusing to act on an unfamiliar row shape would silently leave the alerts split.
function veloFragment(row: Row): { key: string; frag: ScriptBlockFragment } | null {
  const ed = veloEventData(row);
  if (!ed) return null;
  const eid = veloEventId(row);
  if (eid && eid !== 4104) return null;
  const id = str(getCI(ed, "ScriptBlockId")).trim().toLowerCase();
  if (!GUID_RE.test(id)) return null;
  const message = str(getCI(row, "Message") ?? getCI(row, "Details"));
  const header = PART_OF_RE.exec(message);
  const number = num(getCI(ed, "MessageNumber")) || num(header?.[1]);
  const total = num(getCI(ed, "MessageTotal")) || num(header?.[2]);
  if (total < 2) return null; // a whole block in one event — nothing to reassemble
  return {
    key: `${veloHost(row)}|${id}|${veloRuleIdentity(row)}`,
    frag: { id, number, total, text: str(getCI(ed, "ScriptBlockText")) },
  };
}

// Swap the fragment's slice inside the RENDERED message for the whole script, so the description an
// analyst reads — and the message fingerprint the aggregation key is built from — describe the same
// script on every fragment. Three strategies, tried in order, because the rendered form varies with
// Windows locale and with whichever tool re-rendered it:
//   1. the "(N of M):" header is present  → replace everything between it and the "ScriptBlock ID:"
//      trailer, and correct the header itself: left as "(1 of 3)" above the whole script it would
//      tell the analyst the text was truncated, which is the opposite of what happened
//   2. the fragment's slice appears as-is → replace that occurrence
//   3. neither     → append the full script, so the fragments still converge on one text
function rewriteMessage(message: string, chunk: string, full: string, note: string, phrase: string): string {
  if (!message) return message;
  const structured = /^([\s\S]*?\(\d+\s+of\s+\d+\):[ \t]*\r?\n?)([\s\S]*?)(\r?\n\s*ScriptBlock ID:[\s\S]*)$/i;
  const m = structured.exec(message);
  if (m) {
    const header = m[1].replace(PART_OF_RE, `(${phrase} parts, reassembled)`);
    return `${header}${full}${m[3]}`;
  }
  if (chunk && message.includes(chunk)) {
    // Correct the header on the PREFIX only — the part before the fragment's text begins. A blanket
    // replace could rewrite a "(1 of 2)" that occurs inside the script itself, editing evidence.
    const at = message.indexOf(chunk);
    const head = message.slice(0, at).replace(PART_OF_RE, `(${phrase} parts, reassembled)`);
    return `${head}${message.slice(at).split(chunk).join(`${full}${note}`)}`;
  }
  return `${message}\n${full}${note}`;
}

/**
 * Give every fragment row of a multi-part script block the same reassembled script text. Returns a
 * new array of the same length in the same order; rows that are not fragments are passed through
 * untouched (by identity), and no input row is mutated.
 *
 * Expects rows already through `normalizeRow` — the Elastic `Line`/dotted shapes must be un-flattened
 * before the nested `EventData` this reads exists.
 */
export function consolidateVeloScriptBlocks(rows: readonly Row[]): Row[] {
  const frags = rows.map(veloFragment);
  const blocks = reassembleByBlock(frags);
  if (blocks.size === 0) return rows as Row[];
  return rows.map((row, i) => {
    const r = frags[i];
    const block = r ? blocks.get(r.key) : undefined;
    if (!r || !block) return row;
    const ed = veloEventData(row)!;
    const text = `${block.full}${block.note}`;
    const nextEd: Row = { ...ed, ScriptBlockText: text };
    const next: Row = { ...row };
    // Write back into whichever container the row actually carries EventData in — top level, or one
    // of the wrappers. Guessing wrong would leave the real EventData untouched AND invent a sibling
    // key that was never in the row, so the container is resolved rather than assumed.
    const rewrite = (m: string): string =>
      rewriteMessage(m, r.frag.text, block.full, block.note, block.phrase);
    const wrapper = EVENT_WRAPPERS.find((w) => isObject(getPath(row, `${w}.EventData`)));
    if (isObject(getCI(row, "EventData"))) next.EventData = nextEd;
    else if (wrapper) {
      // The wrapper may also carry its OWN rendered message. rowMessage() falls back to it, so
      // leaving it stale keeps the fragment's fingerprint distinct (blocking the very consolidation
      // this performs) and shows the analyst one slice above the full reassembled text.
      const wrapped: Row = { ...(getCI(row, wrapper) as Row), EventData: nextEd };
      const nested = str(getCI(wrapped, "Message"));
      if (nested) wrapped.Message = rewrite(nested);
      next[wrapper] = wrapped;
    } else next.EventData = nextEd;
    // Rewrite EVERY rendered copy the row carries, not just the first one found: `Message` and
    // `Details` can both be present, and a copy left holding one slice contradicts the others.
    for (const key of ["Message", "Details"] as const) {
      const m = str(getCI(row, key));
      if (m) next[key] = rewrite(m);
    }
    return next;
  });
}

// ───────────────────────────── Hayabusa rows ─────────────────────────────

// Hayabusa renders event fields through an output profile, so the same 4104 field arrives under
// different aliases depending on the profile in use ("ScriptBlock" vs "ScrBlk", "MessageNumber" vs
// "MsgNum", …). Keys are matched on their letters and digits alone, so spacing and punctuation in a
// profile's alias do not matter.
const HB_ID_KEYS = new Set(["scriptblockid", "scrblkid", "sbid", "scriptblockguid"]);
const HB_TEXT_KEYS = new Set(["scriptblock", "scriptblocktext", "scrblk", "scrblktext", "script"]);
const HB_NUMBER_KEYS = new Set(["messagenumber", "messagenum", "msgnumber", "msgnum"]);
const HB_TOTAL_KEYS = new Set(["messagetotal", "msgtotal"]);

function normKey(k: string): string {
  return k.replace(/[^a-z0-9]/gi, "").toLowerCase();
}

/**
 * Whether a Hayabusa detail key holds SCRIPT-BLOCK TEXT rather than an ordinary rendered field.
 * Exported because the detail-cell parser has to know: trimming a script slice would discard the
 * script's own edge whitespace, and rejoining the fragments would then glue two tokens together.
 */
export function isScriptBlockTextKey(key: string): boolean {
  return HB_TEXT_KEYS.has(normKey(key));
}

function pickByKeys(details: Row, keys: ReadonlySet<string>): { key: string; value: string } | null {
  for (const [k, v] of Object.entries(details)) {
    if (keys.has(normKey(k))) return { key: k, value: str(v) };
  }
  return null;
}

export interface HayabusaRecord {
  rec: Row;
  details: Row;
  // The joined script, set only on a consolidated fragment. Hayabusa renders each detail field into
  // the description truncated to 120 characters and sets no full-detail message of its own, so
  // without this the merged alert would show LESS script than the split rows did. The importer
  // stamps it onto the event's `message`, where the analyst can expand it.
  fullMessage?: string;
}

function hayabusaFragment(item: HayabusaRecord): { key: string; frag: ScriptBlockFragment } | null {
  const eid = num(getCI(item.rec, "EID") ?? getCI(item.rec, "EventID") ?? getCI(item.rec, "Event ID"));
  if (eid && eid !== 4104) return null;
  const text = pickByKeys(item.details, HB_TEXT_KEYS);
  if (!text) return null;
  // The id normally has its own detail field; when the profile omits it, the rendered text still
  // carries the GUID ("ScriptBlock ID: <guid>"), which is enough to bind the fragments together.
  const idField = pickByKeys(item.details, HB_ID_KEYS);
  const id = (idField?.value.trim() || GUID_RE.exec(text.value)?.[0] || "").toLowerCase();
  if (!GUID_RE.test(id)) return null;
  const header = PART_OF_RE.exec(text.value);
  const number = num(pickByKeys(item.details, HB_NUMBER_KEYS)?.value) || num(header?.[1]);
  const total = num(pickByKeys(item.details, HB_TOTAL_KEYS)?.value) || num(header?.[2]);
  if (total < 2) return null;
  const host = str(getCI(item.rec, "Computer") ?? getCI(item.rec, "Hostname"))
    .trim()
    .toLowerCase();
  const title = str(getCI(item.rec, "RuleTitle") ?? getCI(item.rec, "Title") ?? getCI(item.rec, "RuleName"))
    .trim()
    .toLowerCase();
  return { key: `${host || "?"}|${id}|${title}`, frag: { id, number, total, text: text.value } };
}

/**
 * The Hayabusa counterpart of `consolidateVeloScriptBlocks`, over the `{ rec, details }` pairs the
 * Hayabusa record extractor produces. Same contract: same length, same order, no input mutated.
 */
export function consolidateHayabusaScriptBlocks(items: readonly HayabusaRecord[]): HayabusaRecord[] {
  const frags = items.map(hayabusaFragment);
  const blocks = reassembleByBlock(frags);
  if (blocks.size === 0) return items as HayabusaRecord[];
  return items.map((item, i) => {
    const r = frags[i];
    const block = r ? blocks.get(r.key) : undefined;
    if (!r || !block) return item;
    const textKey = pickByKeys(item.details, HB_TEXT_KEYS)!.key;
    const text = `${block.full}${block.note}`;
    return { rec: item.rec, details: { ...item.details, [textKey]: text }, fullMessage: text };
  });
}
