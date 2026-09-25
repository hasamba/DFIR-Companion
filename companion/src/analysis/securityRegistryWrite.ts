// Security 4657 ("A registry value was modified") names the key in ObjectName and the value in
// ObjectValueName. Neither is in the Windows mapper's rendered-field list, so a 4657 exported with
// no rendered message reached the case with no key anywhere the content tagger reads: `win_run_key`
// could not see a Run-key write and the row stayed Info, out of the forensic timeline (#1670).
//
// Scoped to 4657 on purpose. The rendered-field list is also the aggregation key, and ObjectName is
// carried by 4656 / 4658 / 4660 / 4663 / 5145 and more; adding it to the shared list would change
// the description and the aggregation of every one of them.

type Row = Record<string, unknown>;

const REGISTRY_VALUE_MODIFIED = 4657;
const SUBJECT_KEYS: readonly string[] = ["ObjectName", "ObjectValueName"];

// Case-insensitive, trimmed read of one event_data field; a "-" placeholder reads as empty.
function field(ed: Row, key: string): string {
  const lower = key.toLowerCase();
  const hit = Object.keys(ed).find((k) => k.toLowerCase() === lower);
  const v = hit === undefined ? undefined : ed[hit];
  const s = typeof v === "string" ? v.trim() : typeof v === "number" ? String(v) : "";
  return s === "-" ? "" : s;
}

// The same "is this the Security log" test the mapper's channel label uses. Accepts the provider
// spelling (Microsoft-Windows-Security-Auditing) a `source_name`-only export carries.
function isSecurity4657(channel: string, eid: number): boolean {
  return eid === REGISTRY_VALUE_MODIFIED && /security/i.test(channel) && !/sysmon/i.test(channel);
}

/** The subject keys the mapper appends for this event: ObjectName + ObjectValueName on a 4657 only. */
export function regWriteKeys(base: readonly string[], channel: string, eid: number): string[] {
  return isSecurity4657(channel, eid) ? [...base, ...SUBJECT_KEYS] : [...base];
}

/** The written key as the row's `path`, where the tagger reads it uncapped; `{}` for any other event. */
export function regWritePath(channel: string, eid: number, ed: Row): { path?: string } {
  const key = isSecurity4657(channel, eid) ? field(ed, "ObjectName") : "";
  return key ? { path: key } : {};
}

/** Uncapped key + value-name identity for the aggregation key; the rendered subject caps each at 140. */
export function regWriteIdentity(channel: string, eid: number, ed: Row): string {
  if (!isSecurity4657(channel, eid)) return "";
  const key = field(ed, "ObjectName");
  const value = field(ed, "ObjectValueName");
  return key || value ? `|regkey=${key}|regvalue=${value}` : "";
}
