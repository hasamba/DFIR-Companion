// The analyst's attribution label on an IOC (#2543 part 1b): whose value is this — the attacker's,
// ours (the victim organisation's own asset), the responder's, or unknown. Not `role`:
// `IocRisk.role` (indicator / observation) is a derived score and keeps that name.
//
// The label is ANALYST data and lives in its own per-case side file (iocAttributionStore.ts), never
// in the investigation state a model can write and never in a delta schema. It changes what the
// analyst sees (the IOC panel, the report IOC tables), the block-list export (an `ours` or
// `responder` value is never shipped as a block entry) and, since #2561, which routine forensic rows
// carry a `trusted-activity` tag (trustedSourceMarks.ts) — which synthesis is told about with a
// "not proven benign" marker. It never changes a grade, and a marked source's high-impact actions
// are never tagged, so a wrong label cannot hide an attack.
//
// Keyed by the lower-cased IOC value, not the IOC id: ids are re-sequenced and merged, values are
// what the analyst labelled. A value merged onto another IOC (`aliasValues`) still resolves.

import type { IOC } from "./stateTypes.js";

export const IOC_ATTRIBUTION_LABELS = ["attacker", "ours", "responder", "unknown"] as const;
export type IocAttributionLabel = (typeof IOC_ATTRIBUTION_LABELS)[number];

/** Labels that mark a value as the victim's or the responder's own — never a block-list entry. */
export const FRIENDLY_ATTRIBUTIONS: ReadonlySet<IocAttributionLabel> = new Set(["ours", "responder"]);

export interface IocAttributionEntry {
  value: string; // the value as the analyst labelled it (display)
  label: IocAttributionLabel;
  setAt: string;
  setBy: string;
}

/** Lower-cased value → entry. */
export type IocAttributionMap = Readonly<Record<string, IocAttributionEntry>>;

export const IOC_ATTRIBUTION_VALUE_MAX = 2048;
const ACTOR_MAX = 120;

export function isIocAttributionLabel(v: unknown): v is IocAttributionLabel {
  return typeof v === "string" && (IOC_ATTRIBUTION_LABELS as readonly string[]).includes(v);
}

export function attributionKey(value: string): string {
  return value.trim().toLowerCase();
}

/** A request value, trimmed, one line and bounded; null when unusable. */
export function cleanAttributionValue(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const t = v.trim();
  if (!t || t.length > IOC_ATTRIBUTION_VALUE_MAX || /[\r\n]/.test(t)) return null;
  return t;
}

export function cleanActor(v: unknown): string {
  return typeof v === "string"
    ? v
        .replace(/[\r\n\t]+/g, " ")
        .trim()
        .slice(0, ACTOR_MAX)
    : "";
}

/** Drop every malformed entry from a loaded file; the file is analyst data, but still input. */
export function sanitizeAttributionMap(raw: unknown): IocAttributionMap {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const out: Record<string, IocAttributionEntry> = {};
  for (const e of Object.values(raw as Record<string, unknown>)) {
    if (!e || typeof e !== "object") continue;
    const r = e as Record<string, unknown>;
    const value = cleanAttributionValue(r.value);
    if (!value || !isIocAttributionLabel(r.label)) continue;
    out[attributionKey(value)] = {
      value,
      label: r.label,
      setAt: typeof r.setAt === "string" ? r.setAt : "",
      setBy: cleanActor(r.setBy),
    };
  }
  return out;
}

/** The label for an IOC: its own value first, then any value merged onto it. */
export function attributionFor(
  ioc: Pick<IOC, "value" | "aliasValues">,
  map: IocAttributionMap,
): IocAttributionLabel | undefined {
  const own = map[attributionKey(String(ioc.value ?? ""))];
  if (own) return own.label;
  for (const a of ioc.aliasValues ?? []) {
    const hit = map[attributionKey(a)];
    if (hit) return hit.label;
  }
  return undefined;
}

/** Report projection: each IOC with its label stamped on. Pure — returns new objects. */
export function withIocAttribution<T extends IOC>(iocs: readonly T[], map: IocAttributionMap): T[] {
  if (!Object.keys(map).length) return [...iocs];
  return iocs.map((i) => {
    const label = attributionFor(i, map);
    return label ? { ...i, attribution: label } : i;
  });
}
