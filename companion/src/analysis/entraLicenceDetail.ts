// The licence detail a UAL "Update user" record carries outside its ModifiedProperties (#2604).
//
// Entra writes the licence change (AssignedLicense, AssignedPlan) into
// `ExtendedProperties[].additionalDetails`, three JSON layers deep: the value is JSON, its `b` is a
// JSON string, and that string's `targetUpdatedProperties` is a JSON string holding the array of
// `{Name, OldValue, NewValue}` entries. A large detail is CHUNKED across records (`seq` n of `c`,
// `b` cut at 10,000 characters), so the first chunk's `b` does not parse on its own. Only the
// first chunk starts the array; its complete leading entries are recovered (AssignedLicense comes
// first and is short) and every entry that is cut, or any later chunk, yields nothing. Bounded,
// never throws: a value over the bound, malformed JSON or a cut entry is simply not read.
//
// It also reads a licence string — `[SkuName=…, AccountId=…, SkuId=<guid>, DisabledPlans=[A,B]]` —
// into its SKU id and disabled plan set, the same string the Graph `AssignedLicense` property holds.

type Row = Record<string, unknown>;

export interface DetailUpdate {
  name: string;
  oldValue: unknown;
  newValue: unknown;
}

export interface Licence {
  skuId: string;
  skuName: string;
  disabledPlans: string[];
}

const RAW_MAX = 65_536;
const ELEMENTS_MAX = 32;
const ESCAPES: Record<string, string> = {
  '"': '"',
  "\\": "\\",
  "/": "/",
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
};
const GUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const SKU_ID = new RegExp(`\\bSkuId=(${GUID})(?=[,\\]\\s])`, "gi");
const DISABLED = /\bDisabledPlans=\[([^\][]*)\]/gi;
const SKU_NAME = /\bSkuName=([^,\][]*)/i;

const isObject = (v: unknown): v is Row => typeof v === "object" && v !== null && !Array.isArray(v);
const getCI = (row: Row, key: string): unknown => {
  const lower = key.toLowerCase();
  const k = Object.keys(row).find((x) => x.toLowerCase() === lower);
  return k === undefined ? undefined : row[k];
};
const tryJson = (s: string): unknown => {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
};

/** The text of a JSON string field at the start of a CUT object (`{"key":"…`), unescaped to where it is cut. */
function recoverStringField(cut: string, key: string): string {
  const prefix = `{"${key}":"`;
  if (!cut.startsWith(prefix)) return "";
  let out = "";
  for (let i = prefix.length; i < cut.length; i++) {
    const ch = cut[i];
    if (ch === '"') return out; // the string ended: the whole value is here
    if (ch !== "\\") {
      out += ch;
      continue;
    }
    const next = cut[i + 1];
    if (next === undefined) break;
    if (next === "u") {
      const hex = cut.slice(i + 2, i + 6);
      if (!/^[0-9a-f]{4}$/i.test(hex)) break;
      out += String.fromCharCode(parseInt(hex, 16));
      i += 5;
      continue;
    }
    if (!(next in ESCAPES)) break;
    out += ESCAPES[next];
    i += 1;
  }
  return out;
}

/** The complete object/array elements at the start of a JSON array that may be cut short. */
function completeElements(text: string): string[] {
  const t = text.trimStart();
  if (!t.startsWith("[")) return [];
  const out: string[] = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;
  for (let i = 1; i < t.length && out.length < ELEMENTS_MAX; i++) {
    const ch = t[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
    } else if (ch === '"') inString = true;
    else if (ch === "{" || ch === "[") {
      if (depth === 0) start = i;
      depth += 1;
    } else if (ch === "}" || ch === "]") {
      if (depth === 0) break; // the top-level array closed
      depth -= 1;
      if (depth === 0 && start >= 0) out.push(t.slice(start, i + 1));
    }
  }
  return out;
}

function innerArrayText(details: Row): string {
  const direct = getCI(details, "targetUpdatedProperties");
  if (typeof direct === "string") return direct;
  const b = getCI(details, "b");
  const seq = String(getCI(details, "seq") ?? "1").trim();
  if (typeof b !== "string" || seq !== "1") return "";
  const whole = tryJson(b);
  if (isObject(whole)) {
    const inner = getCI(whole, "targetUpdatedProperties");
    return typeof inner === "string" ? inner : "";
  }
  return recoverStringField(b, "targetUpdatedProperties");
}

/** The `targetUpdatedProperties` entries a UAL record's additionalDetails holds completely. */
export function additionalDetailUpdates(rec: Row): DetailUpdate[] {
  const ext = getCI(rec, "ExtendedProperties");
  const entry = (Array.isArray(ext) ? ext : []).find(
    (e) => isObject(e) && String(getCI(e, "Name") ?? "").toLowerCase() === "additionaldetails",
  );
  const value = isObject(entry) ? getCI(entry, "Value") : undefined;
  if (typeof value !== "string" || value.length > RAW_MAX) return [];
  const details = tryJson(value);
  if (!isObject(details)) return [];
  return completeElements(innerArrayText(details)).flatMap((el) => {
    const o = tryJson(el);
    if (!isObject(o) || typeof getCI(o, "Name") !== "string") return [];
    return [
      { name: String(getCI(o, "Name")), oldValue: getCI(o, "OldValue"), newValue: getCI(o, "NewValue") },
    ];
  });
}

/** A licence string's SKU and disabled plans; null unless it names exactly one of each. */
export function parseLicence(s: unknown): Licence | null {
  if (typeof s !== "string" || s.length > 4096 || !/^\s*\[.*\]\s*$/s.test(s)) return null;
  const skus = [...s.matchAll(SKU_ID)];
  const disabled = [...s.matchAll(DISABLED)];
  if (skus.length !== 1 || disabled.length !== 1) return null;
  const plans = disabled[0][1]
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
  return {
    skuName: (SKU_NAME.exec(s)?.[1] ?? "").trim(),
    skuId: skus[0][1].toLowerCase(),
    disabledPlans: plans,
  };
}
