// Resolve a structured collection directive (investigation-guidance #8, phase 3) to a deployable
// Velociraptor CLIENT VQL, so the dashboard Deploy button can launch the exact collection the AI
// recommended. PURE — no I/O. Returns null when nothing maps (the UI then falls back to a copyable
// manual checklist rather than deploying a guessed artifact).
//
// Priority: (1) an explicit Velociraptor artifact name the model gave (collect.artifact) is used
// verbatim; (2) otherwise keywords in artifact/logSource map onto a known built-in — the forensic
// artifacts come from the verified SHADOW_ARTIFACTS catalog, plus a small hand-verified extra list for
// the common non-anti-forensic sources (event logs, netstat, scheduled tasks). Every artifact name
// here is a real, standard Velociraptor built-in that runs parameterless on a client.

import { SHADOW_ARTIFACTS } from "./shadowArtifacts.js";
import type { CollectDirective } from "./stateTypes.js";

export interface ResolvedCollection {
  vql: string;        // a single deployable CLIENT-side VQL statement
  artifact: string;   // the Velociraptor artifact name it collects (for display + the deploy record)
}

// Looks like a dotted Velociraptor artifact name, e.g. "Windows.EventLogs.Evtx" (optionally "Artifact."-prefixed).
function artifactName(raw: string): string | null {
  const s = raw.trim().replace(/^Artifact\./i, "");
  return /^[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)+$/.test(s) ? s : null;
}

// Hand-verified common built-ins NOT covered by the anti-forensic SHADOW_ARTIFACTS catalog. Keywords are
// matched case-insensitively against the combined artifact + logSource text.
const EXTRA_ARTIFACTS: ReadonlyArray<{ re: RegExp; artifact: string }> = [
  { re: /(security\.evtx|system\.evtx|application\.evtx|\bevtx\b|event ?logs?|\b4624\b|\b4672\b|\b4688\b|\b4648\b|\b4634\b|\b4104\b|\b7045\b)/i, artifact: "Windows.EventLogs.Evtx" },
  { re: /(\bnetstat\b|network connections?|active connections?)/i, artifact: "Windows.Network.Netstat" },
  { re: /(scheduled tasks?|\bschtasks\b|task scheduler)/i, artifact: "Windows.System.TaskScheduler" },
  { re: /(process list|running processes?|\bpslist\b|process listing)/i, artifact: "Windows.System.Pslist" },
];

// Build shadow-catalog keyword matchers once: match on the kebab id, the id with spaces, and the first
// word of the display name (e.g. "usn-journal" / "usn journal" / "usn").
const SHADOW_MATCHERS = SHADOW_ARTIFACTS.map((a) => ({
  keys: [a.id, a.id.replace(/-/g, " "), a.name.toLowerCase().split(/[^a-z0-9$]+/i)[0]].filter(Boolean),
  vql: a.vql,
  artifact: a.velociraptorArtifact,
}));

export function resolveCollectVql(collect: CollectDirective | undefined): ResolvedCollection | null {
  if (!collect) return null;
  const explicit = collect.artifact ? artifactName(collect.artifact) : null;
  if (explicit) return { vql: `SELECT * FROM Artifact.${explicit}()`, artifact: explicit };

  const text = `${collect.artifact ?? ""} ${collect.logSource ?? ""}`;
  for (const e of EXTRA_ARTIFACTS) {
    if (e.re.test(text)) return { vql: `SELECT * FROM Artifact.${e.artifact}()`, artifact: e.artifact };
  }
  const lower = text.toLowerCase();
  for (const m of SHADOW_MATCHERS) {
    if (m.keys.some((k) => k.length >= 3 && lower.includes(k))) return { vql: m.vql, artifact: m.artifact };
  }
  return null;
}
