// Declarative, user-authored importer definition. Pure data — never executed. Validated with Zod
// on load so a hand-written / LLM-generated file fails LOUDLY with field-pathed errors the analyst
// can paste back to an LLM to fix. See declarativeImporter.ts for the interpreter.
import { z } from "zod";
import { checkRegexSafety } from "./regexSafety.js";

// Every kind the detector can return. This array is the single source of truth: importDetect.ts
// derives its `ImportKind` union from it, and BUILTIN_KINDS below is built from it, so the list
// that DEFINES a kind and the list that FORBIDS a custom importer from shadowing it cannot differ.
// They were two hand-maintained copies and they drifted: okta, gws, hindsight, macos, leapp and
// yara were detector kinds absent from BUILTIN_KINDS, so a custom spec could claim one of those ids
// and displace the built-in importer for every file that detected as it — silently, because the
// shadow check passed. Add a kind HERE and both halves move together.
export const IMPORT_KINDS = [
  "thor",
  "siem",
  "evtxxml",
  "chainsaw",
  "hayabusa",
  "ecar",
  "velociraptor",
  "securityonion",
  "socrates",
  "network",
  "kape",
  "cybertriage",
  "m365",
  "okta",
  "gws",
  "hindsight",
  "macos",
  "leapp",
  "aws",
  "cloud",
  "k8s",
  "osquery",
  "plaso",
  "sandbox",
  "memory",
  "email",
  "auditd",
  "journald",
  "sysdig",
  "wazuh",
  "thehive",
  "bashhistory",
  "snort",
  "yara",
  "combinedlog",
  "asa",
  "syslog",
  "csv",
  "log",
  "unknown",
] as const;

// The built-in kinds a custom importer id must NOT shadow — every kind, by construction.
export const BUILTIN_KINDS: ReadonlySet<string> = new Set(IMPORT_KINDS);

const severityEnum = z.enum(["Critical", "High", "Medium", "Low", "Info"]);
const transformEnum = z.enum(["trim", "lowercase", "basename", "cleanIp", "defang", "refang"]);

const fieldBinding = z
  .object({
    from: z.array(z.string().min(1)).min(1),
    format: z.enum(["epoch_s", "epoch_ms", "iso", "auto"]).optional(),
    transform: transformEnum.optional(),
    join: z.string().optional(),
  })
  .strict();

const severityBinding = z.union([
  severityEnum,
  z
    .object({
      from: z.array(z.string().min(1)).min(1),
      map: z.record(z.string(), severityEnum).optional(),
      default: severityEnum.optional(),
    })
    .strict(),
]);

const iocRule = z.union([
  z
    .object({
      type: z.enum(["ip", "domain", "hash", "file", "process", "url", "other"]),
      from: z.array(z.string().min(1)).min(1),
      transform: transformEnum.optional(),
    })
    .strict(),
  z.object({ autoExtract: z.array(z.string().min(1)).min(1) }).strict(),
]);

const matchSpec = z
  .object({
    format: z.enum(["csv", "json", "ndjson", "auto"]).default("auto"),
    requireHeaders: z.array(z.string().min(1)).min(1).optional(),
    anyHeaders: z.array(z.string().min(1)).min(1).optional(),
    requireKeys: z.array(z.string().min(1)).min(1).optional(),
    anyKeys: z.array(z.string().min(1)).min(1).optional(),
    keyEquals: z.record(z.string(), z.string()).optional(),
    filenamePattern: z.string().optional(),
    priority: z.number().int().default(100),
  })
  .strict()
  .superRefine((m, ctx) => {
    if (!(
      m.requireHeaders ||
      m.anyHeaders ||
      m.requireKeys ||
      m.anyKeys ||
      m.keyEquals ||
      m.filenamePattern
    )) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "match needs at least one discriminator (requireHeaders/anyHeaders/requireKeys/anyKeys/keyEquals/filenamePattern)",
      });
    }
    // Vet every user regex HERE rather than at compile time in declarativeImporter, so a
    // catastrophic-backtracking pattern is a loud 400 on POST /importers (never persisted) and a
    // named entry in the GET /importers errors list — not a silently disabled importer.
    const patterns: [string[], string][] = [];
    if (m.filenamePattern !== undefined) patterns.push([["filenamePattern"], m.filenamePattern]);
    for (const [k, p] of Object.entries(m.keyEquals ?? {})) patterns.push([["keyEquals", k], p]);
    for (const [path, src] of patterns) {
      const r = checkRegexSafety(src);
      if (!r.ok) ctx.addIssue({ code: z.ZodIssueCode.custom, path, message: r.reason ?? "unsafe regex" });
    }
  });

const mapSpec = z
  .object({
    timestamp: fieldBinding,
    description: z.string().min(1),
    severity: severityBinding.optional(),
    asset: fieldBinding.optional(),
    user: fieldBinding.optional(),
    processName: fieldBinding.optional(),
    parentName: fieldBinding.optional(),
    sha256: fieldBinding.optional(),
    md5: fieldBinding.optional(),
    path: fieldBinding.optional(),
    srcIp: fieldBinding.optional(),
    dstIp: fieldBinding.optional(),
    port: fieldBinding.optional(),
    mitre: z
      .union([fieldBinding, z.object({ fixed: z.array(z.string().min(1)).min(1) }).strict()])
      .optional(),
    iocs: z.array(iocRule).optional(),
  })
  .strict();

export const importerSpecSchema = z
  .object({
    id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/, "id must be kebab-case (a-z, 0-9, -)"),
    label: z.string().min(1),
    version: z.literal(1).default(1),
    description: z.string().optional(),
    match: matchSpec,
    map: mapSpec,
    options: z
      .object({
        aggregate: z.boolean().default(true),
        minSeverity: severityEnum.optional(),
        maxEvents: z.number().int().positive().optional(),
        maxIocs: z.number().int().positive().optional(),
      })
      .strict()
      .default({ aggregate: true }),
  })
  .strict()
  .refine((s) => !BUILTIN_KINDS.has(s.id), {
    message: "id collides with a built-in importer kind",
    path: ["id"],
  });

export type ImporterSpec = z.infer<typeof importerSpecSchema>;

export interface SpecParseError {
  path: string;
  message: string;
}

export function parseImporterSpec(
  input: unknown,
): { ok: true; spec: ImporterSpec } | { ok: false; errors: SpecParseError[] } {
  const r = importerSpecSchema.safeParse(input);
  if (r.success) return { ok: true, spec: r.data };
  return {
    ok: false,
    errors: r.error.issues.map((i) => ({ path: i.path.join(".") || "(root)", message: i.message })),
  };
}

// The single worked example — embedded in the LLM-authoring prompt AND shipped as a fixture, so the
// few-shot can never drift from the schema (a test parses this object).
export const EXAMPLE_IMPORTER_SPEC = {
  id: "mde-advanced-hunting",
  label: "Microsoft Defender XDR — Advanced Hunting",
  version: 1,
  description: "MDE advanced hunting CSV/JSON export",
  match: {
    format: "csv",
    requireHeaders: ["Timestamp", "DeviceName"],
    anyHeaders: ["ActionType", "FileName"],
    priority: 50,
  },
  map: {
    timestamp: { from: ["Timestamp"], format: "auto" },
    description: "{{ActionType}} on {{DeviceName}} — {{FileName}}",
    severity: {
      from: ["Severity"],
      map: { high: "High", medium: "Medium", informational: "Info" },
      default: "Medium",
    },
    asset: { from: ["DeviceName"] },
    user: { from: ["AccountDomain", "AccountName"], join: "\\" },
    processName: { from: ["FileName"] },
    sha256: { from: ["SHA256"] },
    mitre: { from: ["AttackTechniques"] },
    iocs: [
      { type: "hash", from: ["SHA256", "MD5"] },
      { type: "ip", from: ["RemoteIP"], transform: "cleanIp" },
    ],
  },
  options: { aggregate: true, maxEvents: 2000 },
} as const;
