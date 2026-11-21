// Caps a title at `max` characters (ellipsis included) without cutting inside a word. A word the cap
// would split (an email, user or host name) is dropped whole: a fragment such as the first half of an
// email matches no anonymiser detector, so it would survive into the redacted export while the full
// value is tokenised everywhere else. A first word longer than the cap is dropped too, leaving only
// the ellipsis: half a word is the same leak whether or not a boundary precedes it.
export function capAtWord(text: string, max: number): string {
  const t = text.trim();
  if (t.length <= max) return t;
  const head = t.slice(0, max - 1);
  const splitsWord = !/\s/.test(t[max - 1]);
  const lastSpace = head.search(/\s\S*$/);
  const kept = !splitsWord ? head : lastSpace > 0 ? head.slice(0, lastSpace) : "";
  return kept.trimEnd() + "…";
}
