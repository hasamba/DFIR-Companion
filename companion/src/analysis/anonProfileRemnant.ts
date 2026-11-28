import { locateSecrets } from "./anonSecretCustom.js";

// The rest of a profile name after a redacted value (#3067). A stored-credential value such as
// `-Value C:\Users\<name>` is hidden one way, prefix and all, so the profile pass no longer sees the
// rest of the name when the value stopped short of the name's own end (`C:\Users\<name> x <user>0::2`):
// that rest, which the profile name held as one USER token before the value was hidden, went out in
// clear. The redaction marks such a placeholder; the profile pass then mints the text after it up to
// the profile name's stop, as it would have minted the name.

const REMNANT_MARK = "\uE003"; // a private-use character, never left in the output
const REMNANT_MARK_RE = /\uE003/g;
// The profile prefixes and the name's stop characters of USER_PATH_RE (anonUsernames.ts).
const PROFILE_PREFIX = /[A-Za-z]:\\Users\\|\\Users\\|\/home\/|\/Users\/|\/root\//g;
const NAME_STOP = /[\\/\r\n"'<>|:*?]/;
// The rest after a mark: up to a stop, an IPv6 placeholder or another secret.
const REMNANT_RE = /\uE003([^\\/\r\n"'<>|:*?\uE000\uE001\uE003]*)/g;
const EDGE_SPACE = /^(\s*)([\s\S]*?)(\s*)$/;

/** True when the secret at [start, end) of `clear` ends inside a profile name that runs on past it. */
function endsInProfileName(clear: string, start: number, end: number): boolean {
  const next = clear[end];
  if (next === undefined || NAME_STOP.test(next)) return false;
  const value = clear.slice(start, end);
  let nameAt = -1;
  for (const m of value.matchAll(PROFILE_PREFIX)) nameAt = m.index + m[0].length;
  return nameAt > 0 && nameAt < value.length && !NAME_STOP.test(value.slice(nameAt));
}

export interface ProfileRemnants {
  /**
   * Mark each bare secret placeholder of `redacted` whose secret in `clear` ends inside a profile name
   * that runs on past it. Nothing is marked where the two cannot be lined up exactly, or when the
   * input holds the mark character itself (it is kept, and never read as a mark).
   */
  mark(clear: string, redacted: string, sentinel: string): string;
  /** Mint the rest after each mark with `mint` (its edge spaces stay outside). */
  mint(text: string, mint: (name: string) => string): string;
  /** The text without the marks no pass consumed; ends the call. */
  finish(text: string): string;
}

/** One per anonymizer: `mark`, `mint` and `finish` run in that order within one call. */
export function createProfileRemnants(): ProfileRemnants {
  let marked = false;
  return {
    mark(clear, redacted, sentinel) {
      marked = false;
      if (clear.includes(REMNANT_MARK) || !redacted.includes(sentinel)) return redacted;
      const spans = locateSecrets(clear, redacted, sentinel);
      if (!spans) return redacted;
      let k = 0;
      return redacted.replace(new RegExp(`"${sentinel}"|${sentinel}`, "g"), (form) => {
        const s = spans[k++];
        const exact = s && s.exact.start === s.loose.start && s.exact.end === s.loose.end;
        const mark = form === sentinel && exact && endsInProfileName(clear, s.exact.start, s.exact.end);
        marked ||= mark;
        return mark ? form + REMNANT_MARK : form;
      });
    },
    mint(text, mint) {
      if (!marked) return text;
      return text.replace(REMNANT_RE, (_m, name: string) => {
        const [, lead = "", core = "", trail = ""] = EDGE_SPACE.exec(name) ?? [];
        return core ? lead + mint(core) + trail : name;
      });
    },
    finish(text) {
      const out = marked ? text.replace(REMNANT_MARK_RE, "") : text;
      marked = false;
      return out;
    },
  };
}
