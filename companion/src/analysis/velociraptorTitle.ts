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
// (".S.h.e.l.l.C.l.a.s.s.I.n.f.o......."). Registry noise, not an attacker command — drop it
// rather than show it garbled.
export function isMangledUtf16(s: string): boolean {
  if (s.length < 12) return false;
  const dots = (s.match(/\./g) || []).length;
  return dots / s.length > 0.3;
}
