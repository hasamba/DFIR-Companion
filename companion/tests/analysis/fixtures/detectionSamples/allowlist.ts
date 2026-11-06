// Reads and validates data/detection-overlap-allow.yaml (#2348). Every entry names two grading
// paths and says why their disagreement is intended (or awaits a decision).
import { parse } from "yaml";
import { pairKey } from "./overlap.js";

export interface AllowEntry {
  rules: [string, string];
  reason: string;
  key: string;
}

const PATH = /^(?:importer:(?:cloudtrail|m365|gcp)|sigma:[0-9a-f-]{36}|tagger:[A-Za-z0-9_.-]+)$/;

/** The entries, or an Error naming every malformed one. */
export function readAllowlist(text: string): AllowEntry[] {
  const doc = (parse(text) ?? {}) as { entries?: unknown };
  const raw = doc.entries ?? [];
  if (!Array.isArray(raw)) throw new Error("detection-overlap-allow.yaml: `entries` must be a list");
  const problems: string[] = [];
  const out = raw.flatMap((e: unknown, i): AllowEntry[] => {
    const entry = (e ?? {}) as { rules?: unknown; reason?: unknown };
    const rules = entry.rules;
    const reason = typeof entry.reason === "string" ? entry.reason.trim() : "";
    const ok =
      Array.isArray(rules) &&
      rules.length === 2 &&
      rules.every((r) => typeof r === "string" && PATH.test(r)) &&
      rules[0] !== rules[1];
    if (!ok)
      problems.push(
        `entry ${i + 1}: \`rules\` must name two different paths (importer:<kind>, sigma:<id>, tagger:<id>)`,
      );
    if (!reason) problems.push(`entry ${i + 1}: \`reason\` is required`);
    if (!ok || !reason) return [];
    const [a, b] = rules as [string, string];
    return [{ rules: [a, b], reason, key: pairKey(a, b) }];
  });
  const seen = new Set<string>();
  for (const e of out) {
    if (seen.has(e.key)) problems.push(`duplicate entry for ${e.key}`);
    seen.add(e.key);
  }
  if (problems.length) throw new Error(`detection-overlap-allow.yaml:\n  ${problems.join("\n  ")}`);
  return out;
}
