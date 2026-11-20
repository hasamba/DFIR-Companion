// AI Agent Forensics (#2690): the versioned row contract between the generated Velociraptor artifact
// (integrations/velociraptor/aiAgentArtifact.ts) and the Companion. Every row the artifact emits
// carries the marker column `DFIRCompanionAIAgent` (the schema version) and a `Kind`:
//
//   hit        — a YARA or Sigma match: rule, file, file times and hash, a bounded matched snippet;
//   inventory  — an AI tool present, or one configured MCP server (name + executable only);
//   credential — a credential store present: path, size, modified time, SHA-256 — never contents;
//   coverage   — what ran and what did not on this endpoint (Sysmon absent, a scope with no files…).
//
// The column names are chosen to stay clear of what the shared Velociraptor mappers harvest:
// no `Rule`+`Strings`/`Meta` (that routes to the YARA mapper), no `Message`/`Details` (read into
// event messages and agg fingerprints) and no `HitContext` (decoded into descriptions). The matched
// snippet lives in `MatchedText`, which ONLY the run report reads — never an event (aiAgentImport.ts).

import { z } from "zod";

export const AI_AGENT_MARKER = "DFIRCompanionAIAgent";
export const AI_AGENT_SCHEMA_VERSION = 1;
export const AI_AGENT_SNIPPET_MAX = 200;
const PATH_MAX = 2048;
const TEXT_MAX = 512;

const text = (max: number) =>
  z
    .union([z.string(), z.number()])
    .transform((v) => String(v).slice(0, max))
    .optional();
const num = z.union([z.number(), z.string()]).transform(Number).pipe(z.number().finite()).optional();
const sha = z
  .string()
  .transform((s) => s.trim().toLowerCase())
  .pipe(z.string().regex(/^[0-9a-f]{64}$/))
  .optional()
  .catch(undefined);

const common = {
  [AI_AGENT_MARKER]: z.union([z.number(), z.string()]).transform(Number).pipe(z.number().int().positive()),
  RuleSet: text(TEXT_MAX),
  ScanTime: text(64),
};

export const aiAgentHitRow = z
  .object({
    ...common,
    Kind: z.literal("hit"),
    Family: z.enum(["yara", "sigma"]),
    RuleName: z.string().min(1).max(TEXT_MAX),
    RuleFile: text(TEXT_MAX),
    RuleAuthor: text(TEXT_MAX),
    RuleAtlas: text(TEXT_MAX),
    RuleTags: text(TEXT_MAX),
    Grade: text(16),
    Scope: text(64),
    FilePath: text(PATH_MAX),
    FileSize: num,
    FileMtime: text(64),
    FileBtime: text(64),
    FileSha256: sha,
    EventTime: text(64),
    MatchedText: text(AI_AGENT_SNIPPET_MAX * 4),
    Preserved: text(64),
  })
  .passthrough();

export const aiAgentInventoryRow = z
  .object({
    ...common,
    Kind: z.literal("inventory"),
    Tool: z.string().min(1).max(TEXT_MAX),
    McpServer: text(TEXT_MAX),
    McpCommand: text(TEXT_MAX),
    McpArgCount: num,
    ConfigPath: text(PATH_MAX),
  })
  .passthrough();

export const aiAgentCredentialRow = z
  .object({
    ...common,
    Kind: z.literal("credential"),
    FilePath: z.string().min(1).max(PATH_MAX),
    FileSize: num,
    FileMtime: text(64),
    FileSha256: sha,
  })
  .passthrough();

export const aiAgentCoverageRow = z
  .object({
    ...common,
    Kind: z.literal("coverage"),
    Source: z.string().min(1).max(TEXT_MAX),
    Status: z.string().min(1).max(TEXT_MAX),
    Detail: text(TEXT_MAX),
    Count: num,
  })
  .passthrough();

export const aiAgentRow = z.discriminatedUnion("Kind", [
  aiAgentHitRow,
  aiAgentInventoryRow,
  aiAgentCredentialRow,
  aiAgentCoverageRow,
]);

export type AiAgentHitRow = z.infer<typeof aiAgentHitRow>;
export type AiAgentInventoryRow = z.infer<typeof aiAgentInventoryRow>;
export type AiAgentCredentialRow = z.infer<typeof aiAgentCredentialRow>;
export type AiAgentCoverageRow = z.infer<typeof aiAgentCoverageRow>;
export type AiAgentRow = z.infer<typeof aiAgentRow>;

/** Case-insensitive column read — exports and pushes may change the column case. */
function columnCI(row: Record<string, unknown>, key: string): unknown {
  if (key in row) return row[key];
  const want = key.toLowerCase();
  for (const k of Object.keys(row)) if (k.toLowerCase() === want) return row[k];
  return undefined;
}

/** True when the row was emitted by the AI Agent Forensics artifact (it carries the marker column). */
export function isAiAgentRow(row: Record<string, unknown>): boolean {
  const v = columnCI(row, AI_AGENT_MARKER);
  return v !== undefined && v !== null && v !== "";
}

/** Validate one marked row. A row from a NEWER schema than this build reads is refused, not guessed. */
export function parseAiAgentRow(
  row: Record<string, unknown>,
): { ok: true; row: AiAgentRow } | { ok: false; error: string } {
  const res = aiAgentRow.safeParse(row);
  if (!res.success) return { ok: false, error: res.error.issues[0]?.message ?? "invalid row" };
  if (res.data[AI_AGENT_MARKER] > AI_AGENT_SCHEMA_VERSION)
    return { ok: false, error: `row schema ${res.data[AI_AGENT_MARKER]} is newer than this build reads` };
  return { ok: true, row: res.data };
}

// Secret-shaped substrings a matched snippet may carry (an MCP config's env block, a pasted key).
// Redacted before the snippet is shown or exported (§13.1); the raw row stays in the evidence file.
const SECRET_PATTERNS: readonly RegExp[] = [
  /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
  /\bhf_[A-Za-z0-9]{20,}/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bAIza[0-9A-Za-z_-]{30,}/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  /(Bearer\s+)[A-Za-z0-9._~+/-]{16,}=*/gi,
  /((?:api[_-]?key|token|secret|password|passwd|authorization)["']?\s*[:=]\s*["']?)[^\s"',;]{8,}/gi,
];

/** The snippet as the panel and the reports show it: secret-shaped runs redacted, length-capped. */
export function redactSnippet(raw: string | undefined): string {
  let s = (raw ?? "").slice(0, AI_AGENT_SNIPPET_MAX * 4);
  for (const re of SECRET_PATTERNS)
    s = s.replace(re, (m, keep?: string) =>
      typeof keep === "string" && m.startsWith(keep) ? `${keep}[redacted]` : "[redacted]",
    );
  return s.length > AI_AGENT_SNIPPET_MAX ? `${s.slice(0, AI_AGENT_SNIPPET_MAX)}…` : s;
}
