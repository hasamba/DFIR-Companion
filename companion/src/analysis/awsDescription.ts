// The fixed-slot description of a CloudTrail row (#931 items 6 and 7).
//
// A description is clipped to 600 characters downstream, and an attacker controls several of the
// strings in it — the principal name, a policy document, a tag selector, a user agent. Appending
// slots in order and clipping at the end lets the attacker-shaped text push the evidence out: the
// outcome, the object changed, the qualifier that says what the record does NOT establish. So the
// slots are laid out with RESERVED BUDGETS: the mandatory ones first, each bounded on its own and
// summing to under 600 in the worst case, the optional, attacker-shaped ones sharing whatever is
// left, in order, each clipped to its share. Nothing mandatory is ever clipped by something optional.

const TOTAL_MAX = 600;
const HEAD_MAX = 120; // `AWS <name> (<src>) by <who ≤ 50> from <ip> in <region>` — the caller bounds who
const POSTURE_MAX = 90; // posture + outcome, adjacent to the head
const OUTCOME_MAX = 40; // `denied (<code ≤ 30>)`
const OBJECT_MAX = 150;
const TAIL_MAX = 70; // `[ua ≤ 30] [root] [<errorCode ≤ 30>]` — the caller bounds each part
const QUALIFIERS_MAX = 130; // sized for the three messages the IAM decoder may need at once (128)
// The caller's identity words (#931 item 5) sit after the head. They are attacker-shaped in part
// (a session name, a source identity) and they are context, not the evidence the row grades on:
// they take whatever the other mandatory slots leave, never more than IDENTITY_MAX, never less
// than IDENTITY_MIN — the mandatory set without them sums to 566 with its separators, so 33
// always remain, and the qualifiers are never the slot that pays for the identity.
const IDENTITY_MAX = 150;
const IDENTITY_MIN = 33;
const OPTIONAL_MAX = [140, 100, 100]; // reading, trust, bindings — attacker-shaped, clipped first
const OPTIONAL_DEFAULT_MAX = 100;

export interface AwsDescriptionParts {
  head: string;
  /** The caller's identity words — kind, credential, issuer, session, accounts. */
  identity?: string;
  posture: string;
  /** `denied (<code>)` on a failed call — rendered next to the posture, never in the tail alone. */
  outcome: string;
  object: string;
  optional: string[];
  tail: string;
  qualifiers: string[];
}

const clip = (s: string, max: number): string => (s.length <= max ? s : `${s.slice(0, max - 1)}…`);

export function renderAwsDescription(parts: AwsDescriptionParts): string {
  const head = clip(parts.head.trim(), HEAD_MAX);
  // The outcome is reserved INSIDE the posture slot: a posture that carries record data (a version
  // id) is clipped to what the outcome leaves, so "denied (…)" is never the part that falls off.
  const outcome = parts.outcome.trim() ? ` — ${clip(parts.outcome.trim(), OUTCOME_MAX)}` : "";
  const posture = `${clip(parts.posture.trim(), POSTURE_MAX - outcome.length)}${outcome}`.trim();
  const object = clip(parts.object.trim(), OBJECT_MAX);
  const tail = clip(parts.tail.trim(), TAIL_MAX);
  const qualifiers = clip(parts.qualifiers.filter(Boolean).join("; "), QUALIFIERS_MAX);
  const fixed = [head, posture, object].filter(Boolean);
  const fixedLen =
    fixed.join(" ").length + (tail ? tail.length + 1 : 0) + (qualifiers ? qualifiers.length + 3 : 0);
  const identityRaw = (parts.identity ?? "").trim();
  const identity = identityRaw
    ? clip(identityRaw, Math.max(IDENTITY_MIN, Math.min(IDENTITY_MAX, TOTAL_MAX - fixedLen - 1)))
    : "";
  const mandatory = [head, identity, posture, object].filter(Boolean);
  let remaining =
    TOTAL_MAX -
    mandatory.join(" ").length -
    (tail ? tail.length + 1 : 0) -
    (qualifiers ? qualifiers.length + 3 : 0);
  const optional: string[] = [];
  parts.optional.forEach((text, i) => {
    const t = text.trim();
    if (!t) return;
    const share = Math.min(OPTIONAL_MAX[i] ?? OPTIONAL_DEFAULT_MAX, remaining - 1);
    if (share < 8) return; // no room for anything legible — the mandatory slots have it
    const shown = clip(t, share);
    optional.push(shown);
    remaining -= shown.length + 1;
  });
  const body = [...mandatory, ...optional, tail].filter(Boolean).join(" ");
  return `${body}${qualifiers ? ` — ${qualifiers}` : ""}`.slice(0, TOTAL_MAX);
}
