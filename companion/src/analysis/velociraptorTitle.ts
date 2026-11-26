// Small, pure helpers for building Velociraptor event titles/descriptions — split out of
// velociraptorImport.ts (see #384's file-size ledger) rather than grown in place.
//
// dashboard-text.js's splitEventTitle keeps only the text before the FIRST literal " - " as the
// row's TITLE; everything after it collapses into the [details] panel. Both helpers below exist
// to keep that boundary where the importer actually intends it.

// The host chip already shows the host, so force it behind a guaranteed " - " boundary.
export function withHostSuffix(description: string, host: string): string {
  if (!host || description.toLowerCase().includes(host.toLowerCase())) return description;
  return description.includes(" - ") ? `${description} @ ${host}` : `${description} - @ ${host}`;
}

// withHostSuffix under a length cap (#2881). Capping AFTER the suffix cut it to a fragment
// ("… @ WS-LA", which could read as another host) whenever the core sat within a suffix-length of
// the cap. Trim the core to leave room instead, so the host is whole — or, only when the host
// alone cannot fit, absent. The suffix grows to " - @ HOST" when the trimmed core loses its " - ".
export function capWithHostSuffix(core: string, host: string, cap: number): string {
  const whole = withHostSuffix(core, host);
  if (whole.length <= cap) return whole;
  const plain = core.slice(0, cap);
  if (!host || withHostSuffix(plain, host) === plain) return plain;
  for (const suffix of [` @ ${host}`, ` - @ ${host}`]) {
    const room = cap - suffix.length;
    if (room <= 0) break;
    const out = withHostSuffix(core.slice(0, room), host);
    if (out.length <= cap) return out;
  }
  return plain;
}

// A ransomware note goes AFTER the host ("… @ HOST — <note> (T1486)"), so the host-suffixed part is
// capped at what the note leaves (#2885); capping the whole string again cut the host on exactly the
// High rows. The note is bounded first: DFIR_RANSOM_EXTS can name an arbitrarily long family.
const RANSOM_NOTE_CAP = 160;
export function ransomTailWithHost(
  core: string,
  host: string,
  note: string | undefined,
  cap: number,
): string {
  if (!note) return capWithHostSuffix(core, host, cap);
  const tail = ` — ${note.slice(0, RANSOM_NOTE_CAP)} (T1486)`;
  return capWithHostSuffix(core, host, Math.max(0, cap - tail.length)) + tail;
}

// Rewrite a description that already ends in its host suffix (the import loop's artifact-name
// injection, #2885) without losing that host to the cap: strip the suffix, transform the core, and
// re-apply it under the cap. A description whose host is not a withHostSuffix suffix (none, part of
// the text, or followed by a former-hostname note) is transformed and capped as before.
export function injectKeepingHost(
  description: string,
  host: string,
  cap: number,
  transform: (core: string) => string,
): string {
  for (const suffix of [` - @ ${host}`, ` @ ${host}`]) {
    if (!host || !description.endsWith(suffix)) continue;
    const core = description.slice(0, -suffix.length);
    if (core.toLowerCase().includes(host.toLowerCase())) break; // not a suffix withHostSuffix added
    return capWithHostSuffix(transform(core), host, cap);
  }
  return transform(description).slice(0, cap);
}

// A rule/verdict NAME can itself contain " - " ("RMM - Microsoft Quick Assist Execution"), which
// would be mistaken for that same boundary and truncate the title. Swap it for an em dash.
export function titleSafe(name: string): string {
  return name.replace(/ - /g, " — ");
}

// A desktop.ini [.ShellClassInfo] entry's Details is raw UTF-16, NUL bytes rendered as "."
// (".S.h.e.l.l.C.l.a.s.s.I.n.f.o......."). Registry noise, not an attacker command.
//
// NEVER just drop a value that LOOKS mangled — a heuristic guess is not grounds to silently
// discard evidence in a forensics tool, and any dot-heavy heuristic (version string, IP, a
// deliberately char-separated LOLBIN evasion attempt) risks a false positive on something real.
// Decode instead: split on ".", where a run of empty segments (a double/triple NUL) marks a
// word boundary and becomes a space, and single-dot gaps between one-character segments just
// collapse. Every original character survives — this only removes the mangling's own noise.
export function demangleUtf16Noise(s: string): string {
  if (s.length < 12 || /[^.]{2,}/.test(s)) return s; // has a real word (2+ chars run) → untouched
  const dots = (s.match(/\./g) || []).length;
  if (dots / s.length <= 0.3) return s;
  let out = "";
  let boundary = false;
  for (const part of s.split(".")) {
    if (part === "") {
      boundary = true;
      continue;
    }
    if (boundary && out) out += " ";
    boundary = false;
    out += part;
  }
  return out.trim() || s;
}
