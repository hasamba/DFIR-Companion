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
