import { createHash } from "node:crypto";
import { z } from "zod";
import type { ForensicEvent } from "./stateTypes.js";

export const CANONICAL_EVENT_SCHEMA_VERSION = "1.0.0" as const;

const confidenceSchema = z.enum(["high", "medium", "low"]);
const entityKindSchema = z.enum([
  "account", "host", "process", "file", "registry", "service", "task",
  "mailbox", "cloud_principal", "network", "other",
]);

export const canonicalEntitySchema = z.object({
  kind: entityKindSchema,
  id: z.string().optional(),
  name: z.string().optional(),
  domain: z.string().optional(),
  address: z.string().optional(),
  port: z.number().int().positive().max(65535).optional(),
});

const canonicalProcessSchema = z.object({
  pid: z.number().int().positive().optional(),
  name: z.string().optional(),
  executable: z.string().optional(),
  commandLine: z.string().optional(),
  parent: z.object({
    pid: z.number().int().positive().optional(),
    name: z.string().optional(),
    executable: z.string().optional(),
  }).optional(),
});

const rawRecordPointerSchema = z.object({
  source: z.string().min(1),
  locator: z.string().min(1),
  recordId: z.string().optional(),
});

const fieldProvenanceSchema = z.object({
  origin: z.enum(["raw", "derived"]),
  confidence: confidenceSchema,
  rawFields: z.array(z.string()).optional(),
  derivation: z.string().optional(),
  recordLocators: z.array(z.string().min(1)).min(1),
});

export const canonicalEventEnvelopeSchema = z.object({
  schemaVersion: z.literal(CANONICAL_EVENT_SCHEMA_VERSION),
  event: z.object({
    category: z.enum([
      "authentication", "process", "network", "file", "registry", "service",
      "task", "email", "cloud", "memory", "other",
    ]),
    type: z.string().min(1),
    action: z.string().optional(),
    outcome: z.string().optional(),
  }),
  actor: canonicalEntitySchema.optional(),
  subject: canonicalEntitySchema.optional(),
  object: canonicalEntitySchema.optional(),
  target: canonicalEntitySchema.optional(),
  account: z.object({
    id: z.string().optional(),
    name: z.string().optional(),
    domain: z.string().optional(),
  }).optional(),
  authentication: z.object({
    sessionId: z.string().optional(),
    logonType: z.number().int().nonnegative().optional(),
    protocol: z.string().optional(),
    mechanism: z.string().optional(),
  }).optional(),
  session: z.object({
    id: z.string().optional(),
    terminal: z.string().optional(),
    interactive: z.boolean().optional(),
  }).optional(),
  network: z.object({
    source: z.object({
      address: z.string().optional(),
      port: z.number().int().positive().max(65535).optional(),
      hostname: z.string().optional(),
    }).optional(),
    destination: z.object({
      address: z.string().optional(),
      port: z.number().int().positive().max(65535).optional(),
      hostname: z.string().optional(),
    }).optional(),
    protocol: z.string().optional(),
  }).optional(),
  process: canonicalProcessSchema.optional(),
  file: z.object({
    path: z.string().optional(),
    name: z.string().optional(),
    sha256: z.string().optional(),
    md5: z.string().optional(),
  }).optional(),
  registry: z.object({
    key: z.string().optional(),
    valueName: z.string().optional(),
    valueData: z.string().optional(),
  }).optional(),
  service: z.object({
    name: z.string().optional(),
    displayName: z.string().optional(),
    executable: z.string().optional(),
  }).optional(),
  task: z.object({
    name: z.string().optional(),
    command: z.string().optional(),
  }).optional(),
  mailbox: z.object({
    messageId: z.string().optional(),
    sender: z.string().optional(),
    recipients: z.array(z.string()).optional(),
    subject: z.string().optional(),
  }).optional(),
  cloud: z.object({
    provider: z.string().optional(),
    principalId: z.string().optional(),
    principalType: z.string().optional(),
    tenant: z.string().optional(),
    accountId: z.string().optional(),
    region: z.string().optional(),
    resource: z.string().optional(),
  }).optional(),
  time: z.object({
    observed: z.string(),
    normalized: z.string(),
    timezone: z.string(),
    precision: z.enum(["date", "minute", "second", "millisecond", "microsecond", "unknown"]),
    clockConfidence: z.enum(["recorded", "inferred", "unknown"]),
  }),
  evidence: z.object({
    rawRecords: z.array(rawRecordPointerSchema).min(1),
    sourceArtifactHash: z.string().regex(/^sha256:[a-f0-9]{64}$/).optional(),
  }),
  producer: z.object({
    importer: z.string().min(1),
    parserVersion: z.string().min(1),
    mappingVersion: z.string().min(1),
    ruleVersions: z.array(z.string()).optional(),
  }),
  fieldProvenance: z.record(fieldProvenanceSchema),
});

export type CanonicalEntity = z.infer<typeof canonicalEntitySchema>;
export type CanonicalEventEnvelope = z.infer<typeof canonicalEventEnvelopeSchema>;
export type CanonicalEventCategory = CanonicalEventEnvelope["event"]["category"];
export type CanonicalFieldProvenance = CanonicalEventEnvelope["fieldProvenance"][string];

type CanonicalNormalizedFields = Omit<
  CanonicalEventEnvelope,
  "schemaVersion" | "evidence" | "producer" | "fieldProvenance"
>;

export type CreateCanonicalEventInput = Omit<CanonicalNormalizedFields, "time"> & {
  time: Pick<CanonicalEventEnvelope["time"], "observed" | "normalized"> &
    Partial<Omit<CanonicalEventEnvelope["time"], "observed" | "normalized">>;
  evidence: CanonicalEventEnvelope["evidence"];
  producer: CanonicalEventEnvelope["producer"];
  rawFieldMap?: Record<string, string[]>;
  confidenceMap?: Record<string, CanonicalFieldProvenance["confidence"]>;
  derivationMap?: Record<string, string>;
};

function timezoneOf(observed: string): string {
  if (/Z$/i.test(observed.trim())) return "UTC";
  const offset = /([+-]\d{2}:?\d{2})$/.exec(observed.trim())?.[1];
  return offset ? offset.replace(/^([+-]\d{2})(\d{2})$/, "$1:$2") : "unknown";
}

function precisionOf(observed: string): CanonicalEventEnvelope["time"]["precision"] {
  const s = observed.trim();
  if (!s) return "unknown";
  const fraction = /[.,](\d+)(?:Z|[+-]\d{2}:?\d{2})?$/.exec(s)?.[1]?.length ?? 0;
  if (fraction > 3) return "microsecond";
  if (fraction > 0) return "millisecond";
  if (/\d{1,2}:\d{2}:\d{2}/.test(s)) return "second";
  if (/\d{1,2}:\d{2}/.test(s)) return "minute";
  if (/\d{4}-\d{2}-\d{2}/.test(s)) return "date";
  return "unknown";
}

function normalizedLeafPaths(value: unknown, prefix = ""): string[] {
  if (value == null) return [];
  if (Array.isArray(value)) return value.length && prefix ? [prefix] : [];
  if (typeof value !== "object") return prefix ? [prefix] : [];
  const out: string[] = [];
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    out.push(...normalizedLeafPaths(child, prefix ? `${prefix}.${key}` : key));
  }
  return out;
}

function normalizedPart(envelope: CanonicalEventEnvelope): CanonicalNormalizedFields {
  const {
    schemaVersion: _schemaVersion,
    evidence: _evidence,
    producer: _producer,
    fieldProvenance: _fieldProvenance,
    ...normalized
  } = envelope;
  return normalized;
}

export function createCanonicalEvent(input: CreateCanonicalEventInput): CanonicalEventEnvelope {
  const {
    rawFieldMap = {},
    confidenceMap = {},
    derivationMap = {},
    ...fields
  } = input;
  const time: CanonicalEventEnvelope["time"] = {
    observed: input.time.observed,
    normalized: input.time.normalized,
    timezone: input.time.timezone ?? timezoneOf(input.time.observed),
    precision: input.time.precision ?? precisionOf(input.time.observed),
    clockConfidence: input.time.clockConfidence ?? (input.time.observed ? "recorded" : "unknown"),
  };
  const base = {
    ...fields,
    time,
  } as CanonicalNormalizedFields & Pick<CanonicalEventEnvelope, "evidence" | "producer">;
  const firstLocator = input.evidence.rawRecords[0]?.locator;
  if (!firstLocator) throw new Error("Canonical events require at least one raw-record locator");
  const fieldProvenance: CanonicalEventEnvelope["fieldProvenance"] = {};
  for (const path of normalizedLeafPaths(base).filter((path) => !path.startsWith("evidence.") && !path.startsWith("producer."))) {
    const rawFields = rawFieldMap[path];
    const derivation = derivationMap[path];
    fieldProvenance[path] = rawFields?.length
      ? {
          origin: "raw",
          confidence: confidenceMap[path] ?? "high",
          rawFields: [...rawFields],
          recordLocators: [firstLocator],
        }
      : {
          origin: "derived",
          confidence: confidenceMap[path] ?? "high",
          derivation: derivation ?? `${input.producer.mappingVersion}: deterministic mapping from referenced raw record`,
          recordLocators: [firstLocator],
        };
  }
  return canonicalEventEnvelopeSchema.parse({
    schemaVersion: CANONICAL_EVENT_SCHEMA_VERSION,
    ...base,
    fieldProvenance,
  });
}

export function canonicalConformanceIssues(envelope: unknown): string[] {
  if (envelope == null) return ["canonical envelope missing"];
  const parsed = canonicalEventEnvelopeSchema.safeParse(envelope);
  if (!parsed.success) {
    return parsed.error.issues.map((issue) =>
      `${issue.path.join(".") || "canonical"}: ${issue.message}`,
    );
  }
  const issues: string[] = [];
  const canonical = parsed.data;
  const rawLocators = new Set(canonical.evidence.rawRecords.map((record) => record.locator));
  for (const path of normalizedLeafPaths(normalizedPart(canonical))) {
    if (!canonical.fieldProvenance[path]) issues.push(`missing field provenance: ${path}`);
  }
  for (const [path, provenance] of Object.entries(canonical.fieldProvenance)) {
    if (provenance.origin === "raw" && !provenance.rawFields?.length) {
      issues.push(`raw provenance has no source field: ${path}`);
    }
    if (provenance.origin === "derived" && !provenance.derivation) {
      issues.push(`derived provenance has no rule: ${path}`);
    }
    for (const locator of provenance.recordLocators) {
      if (!rawLocators.has(locator)) issues.push(`field provenance references an unknown record: ${path} -> ${locator}`);
    }
  }
  return issues;
}

export function sourceArtifactHash(text: string): string {
  return `sha256:${createHash("sha256").update(text).digest("hex")}`;
}

export function stampSourceArtifactHash<T extends { canonical?: CanonicalEventEnvelope }>(
  events: readonly T[],
  text: string,
): T[] {
  const hash = sourceArtifactHash(text);
  return events.map((event) => event.canonical
    ? {
        ...event,
        canonical: {
          ...event.canonical,
          evidence: { ...event.canonical.evidence, sourceArtifactHash: hash },
        },
      }
    : { ...event });
}

export function mergeCanonicalEvents(
  first: CanonicalEventEnvelope | undefined,
  incoming: CanonicalEventEnvelope | undefined,
): CanonicalEventEnvelope | undefined {
  if (!first) return incoming;
  if (!incoming) return first;
  const firstVersion = (first as { schemaVersion?: string }).schemaVersion;
  const incomingVersion = (incoming as { schemaVersion?: string }).schemaVersion;
  if (firstVersion !== CANONICAL_EVENT_SCHEMA_VERSION) return first;
  if (incomingVersion !== CANONICAL_EVENT_SCHEMA_VERSION) return incoming;
  const pointers = [...first.evidence.rawRecords];
  for (const pointer of incoming.evidence.rawRecords) {
    if (!pointers.some((p) => p.source === pointer.source && p.locator === pointer.locator)) pointers.push(pointer);
  }
  const fieldProvenance = { ...first.fieldProvenance };
  for (const [path, provenance] of Object.entries(incoming.fieldProvenance)) {
    const existing = fieldProvenance[path];
    if (!existing) {
      fieldProvenance[path] = provenance;
      continue;
    }
    fieldProvenance[path] = {
      ...existing,
      recordLocators: [...new Set([...(existing.recordLocators ?? []), ...(provenance.recordLocators ?? [])])],
    };
  }
  return {
    ...first,
    evidence: {
      rawRecords: pointers,
      sourceArtifactHash: first.evidence.sourceArtifactHash ?? incoming.evidence.sourceArtifactHash,
    },
    fieldProvenance,
  };
}

interface LegacyLogon {
  account: string;
  outcome: "success" | "failed";
  logonType?: number;
  sourceIp?: string;
  workstation?: string;
  sessionId?: string;
}

const LEGACY_LOGON_MARKER = /(Successful|Failed) logon \(EID (?:4624|4625)\)/;
const LEGACY_ACCOUNT = /(?<![\\/:.\w])(NT AUTHORITY|NT SERVICE|Window Manager|Font Driver Host|[A-Za-z][A-Za-z0-9.-]{1,30})\\([A-Za-z0-9._$-]{2,40})(?![\\/\w])/g;

function legacyLogon(event: ForensicEvent): LegacyLogon | undefined {
  const marker = LEGACY_LOGON_MARKER.exec(event.description);
  if (!marker) return undefined;
  const separator = event.description.indexOf(" - ");
  if (separator !== -1 && marker.index > separator) return undefined;
  const rest = event.description.slice(marker.index + marker[0].length);
  const segment = rest.replace(/^ - /, "").split(/ - (?=[A-Za-z]+=)| @ | \[/)[0]?.trim() ?? "";
  const account = segment.split(", ")[0]?.trim();
  if (!account || account.includes("=")) return undefined;
  const rawType = /\bLogonType=(\d+)\b/.exec(event.description)?.[1];
  const sourceIp = /\bIpAddress=(\S+)/.exec(event.description)?.[1];
  const workstation = /\bWorkstationName=(\S+)/.exec(event.description)?.[1];
  const sessionId = /\b(?:TargetLogonId|LogonId)=(\S+)/.exec(event.description)?.[1];
  return {
    account,
    outcome: marker[1] === "Successful" ? "success" : "failed",
    ...(rawType ? { logonType: Number(rawType) } : {}),
    ...(sourceIp ? { sourceIp } : {}),
    ...(workstation ? { workstation } : {}),
    ...(sessionId ? { sessionId } : {}),
  };
}

function legacyAccount(event: ForensicEvent): string | undefined {
  LEGACY_ACCOUNT.lastIndex = 0;
  const match = LEGACY_ACCOUNT.exec(event.description);
  return match ? `${match[1]}\\${match[2]}` : undefined;
}

function fileName(path: string | undefined): string | undefined {
  return path?.split(/[\\/]/).pop() || undefined;
}

function legacyCanonical(event: ForensicEvent): CanonicalEventEnvelope {
  const logon = legacyLogon(event);
  const accountName = logon?.account ?? legacyAccount(event);
  const category: CanonicalEventCategory = logon
    ? "authentication"
    : event.processName || event.parentName || event.pid || event.commandLine
      ? "process"
      : event.srcIp || event.dstIp
        ? "network"
        : event.path || event.sha256 || event.md5
          ? "file"
          : "other";
  const actor: CanonicalEntity | undefined = accountName
    ? { kind: "account", name: accountName }
    : undefined;
  const target: CanonicalEntity | undefined = event.asset
    ? { kind: "host", name: event.asset }
    : undefined;
  const process = event.processName || event.parentName || event.pid || event.commandLine
    ? {
        ...(event.pid ? { pid: event.pid } : {}),
        ...(event.processName ? { name: event.processName } : {}),
        ...(event.path ? { executable: event.path } : {}),
        ...(event.commandLine ? { commandLine: event.commandLine } : {}),
        ...(event.parentName ? { parent: { name: event.parentName } } : {}),
      }
    : undefined;
  const file = event.path || event.sha256 || event.md5
    ? {
        ...(event.path ? { path: event.path, name: fileName(event.path) } : {}),
        ...(event.sha256 ? { sha256: event.sha256 } : {}),
        ...(event.md5 ? { md5: event.md5 } : {}),
      }
    : undefined;
  const network = event.srcIp || event.dstIp || event.port
    ? {
        ...(event.srcIp ? { source: { address: event.srcIp } } : {}),
        ...(event.dstIp || event.port ? {
          destination: {
            ...(event.dstIp ? { address: event.dstIp } : {}),
            ...(event.port ? { port: event.port } : {}),
          },
        } : {}),
      }
    : undefined;
  return createCanonicalEvent({
    event: {
      category,
      type: logon ? "logon" : category === "process" ? "observation" : category === "network" ? "connection" : category === "file" ? "observation" : "event",
      ...(event.action ? { action: event.action } : {}),
      ...(logon ? { outcome: logon.outcome } : {}),
    },
    ...(actor ? { actor } : {}),
    ...(target ? { target } : {}),
    ...(accountName ? {
      account: {
        name: accountName,
        ...(accountName.includes("\\") ? { domain: accountName.split("\\")[0] } : {}),
      },
    } : {}),
    ...(logon ? {
      authentication: {
        ...(logon.sessionId ? { sessionId: logon.sessionId } : {}),
        ...(logon.logonType !== undefined ? { logonType: logon.logonType } : {}),
      },
      ...(logon.workstation ? { session: { terminal: logon.workstation } } : {}),
    } : {}),
    ...(network || logon?.sourceIp ? {
      network: {
        ...network,
        ...(logon?.sourceIp ? { source: { address: logon.sourceIp } } : {}),
      },
    } : {}),
    ...(process ? { process } : {}),
    ...(file ? { file } : {}),
    time: { observed: event.timestamp, normalized: event.timestamp },
    evidence: {
      rawRecords: [{ source: "legacy-forensic-event", locator: `event:${event.id}`, recordId: event.id }],
    },
    producer: {
      importer: "legacy-upgrade",
      parserVersion: "1",
      mappingVersion: "legacy-event-to-canonical-v1",
    },
    rawFieldMap: {
      "time.observed": ["timestamp"],
      "time.normalized": ["timestamp"],
      ...(event.asset ? { "target.name": ["asset"] } : {}),
      ...(event.processName ? { "process.name": ["processName"] } : {}),
      ...(event.parentName ? { "process.parent.name": ["parentName"] } : {}),
      ...(event.pid ? { "process.pid": ["pid"] } : {}),
      ...(event.commandLine ? { "process.commandLine": ["commandLine"] } : {}),
      ...(event.path ? { "file.path": ["path"] } : {}),
      ...(event.sha256 ? { "file.sha256": ["sha256"] } : {}),
      ...(event.md5 ? { "file.md5": ["md5"] } : {}),
      ...(event.srcIp ? { "network.source.address": ["srcIp"] } : {}),
      ...(event.dstIp ? { "network.destination.address": ["dstIp"] } : {}),
      ...(event.port ? { "network.destination.port": ["port"] } : {}),
    },
    confidenceMap: accountName ? { "actor.name": "medium", "account.name": "medium" } : {},
    derivationMap: {
      ...(accountName ? {
        "actor.name": "legacy-event-to-canonical-v1: one-time guarded identity extraction from legacy display text",
        "account.name": "legacy-event-to-canonical-v1: one-time guarded identity extraction from legacy display text",
      } : {}),
    },
  });
}

export function upgradeForensicEvent(event: ForensicEvent): ForensicEvent {
  if (event.canonical?.schemaVersion === CANONICAL_EVENT_SCHEMA_VERSION) return event;
  // A future major/minor version may contain meaning this build does not understand. Preserve it
  // verbatim instead of silently downgrading it; explicit version migrations are registered here.
  if (event.canonical) return event;
  return { ...event, canonical: legacyCanonical(event) };
}

function currentCanonical(event: ForensicEvent): CanonicalEventEnvelope | undefined {
  const upgraded = upgradeForensicEvent(event);
  return upgraded.canonical?.schemaVersion === CANONICAL_EVENT_SCHEMA_VERSION
    ? upgraded.canonical
    : undefined;
}

export function canonicalAccounts(event: ForensicEvent): string[] {
  const canonical = currentCanonical(event);
  if (!canonical) return [];
  const names = [
    canonical.actor?.kind === "account" ? canonical.actor.name : undefined,
    canonical.subject?.kind === "account" ? canonical.subject.name : undefined,
    canonical.object?.kind === "account" ? canonical.object.name : undefined,
    canonical.target?.kind === "account" ? canonical.target.name : undefined,
    canonical.account?.name,
  ].filter((name): name is string => !!name?.trim());
  return [...new Set(names)];
}

export function canonicalProcess(event: ForensicEvent): CanonicalEventEnvelope["process"] {
  return currentCanonical(event)?.process;
}

export function canonicalNetwork(event: ForensicEvent): CanonicalEventEnvelope["network"] {
  return currentCanonical(event)?.network;
}

export function canonicalFile(event: ForensicEvent): CanonicalEventEnvelope["file"] {
  return currentCanonical(event)?.file;
}
