import { createHash } from "node:crypto";
import { z } from "zod";
import type { ForensicEvent } from "./stateTypes.js";
import { smbBlockSchema, transferBlockSchema, webBlockSchema } from "./canonicalWeb.js";
import { dnsBlockSchema } from "./canonicalDns.js";
import { tlsGraphBlockSchema } from "./canonicalTls.js";
import { quarantineAttributeBlockSchema, quarantineBlockSchema } from "./canonicalQuarantine.js";
import { defenderBlockSchema } from "./canonicalDefender.js";
import { mobileBlockSchema } from "./canonicalMobile.js";
import { entraPathBlockSchema } from "./canonicalEntra.js";
import { awsLineageBlockSchema } from "./canonicalAwsLineage.js";
import { awsComputeBlockSchema } from "./canonicalAwsCompute.js";
import { azureComputeBlockSchema, azureVmssComputeBlockSchema } from "./canonicalAzureCompute.js";
import { gcpComputeBlockSchema } from "./canonicalGcpCompute.js";
import { gcpBlockSchema } from "./canonicalGcp.js";
import { gcpServiceAccountJoinBlockSchema } from "./canonicalGcpServiceAccountJoin.js";
import { loggingChangeBlockSchema } from "./canonicalLogging.js";
import { acquisitionCoverageBlockSchema } from "./canonicalAcquisition.js";
import { diskImageAcquisitionSchema } from "./canonicalDiskImage.js";
import {
  driveAccessBlockSchema,
  driveExposureBlockSchema,
  driveSharingBlockSchema,
  takeoutBlockSchema,
  takeoutLifecycleBlockSchema,
} from "./canonicalGwsDrive.js";
import { mailboxChainBlockSchema } from "./canonicalMailbox.js";
import { memoryRunBlockSchema } from "./canonicalMemoryRun.js";
import { gwsLifecycleBlockSchema } from "./canonicalGwsLifecycle.js";
import { recoveredFragmentBlockSchema } from "./canonicalRecoveredFragment.js";
import { decodedStringBlockSchema } from "./canonicalDecodedString.js";
import { capaMatchBlockSchema, capaCompositeLeadBlockSchema } from "./canonicalCapaMatch.js";
import {
  olevbaFindingBlockSchema,
  olevbaStompingLeadBlockSchema,
  olevbaCompoundLeadBlockSchema,
} from "./canonicalOlevbaFinding.js";
import { sqliteRowStateBlockSchema } from "./canonicalSqliteRowState.js";

export const CANONICAL_EVENT_SCHEMA_VERSION = "1.0.0" as const;
/** The producer stamped on an envelope DERIVED from legacy flat fields at the read boundary. */
export const LEGACY_UPGRADE_IMPORTER = "legacy-upgrade";

const confidenceSchema = z.enum(["high", "medium", "low"]);
const entityKindSchema = z.enum([
  "account",
  "host",
  "process",
  "file",
  "registry",
  "service",
  "task",
  "mailbox",
  "cloud_principal",
  "network",
  "other",
]);

export const canonicalEntitySchema = z.object({
  kind: entityKindSchema,
  id: z.string().optional(),
  name: z.string().optional(),
  domain: z.string().optional(),
  address: z.string().optional(),
  port: z.number().int().positive().max(65535).optional(),
  /** A process entity's pid — a source or target process in a two-process relation (#932 item 3). */
  pid: z.number().int().positive().optional(),
});

const canonicalProcessSchema = z.object({
  /** The process GUID a Sysmon record carries (processAccess.ts normalises it) — the sequence join's identity (#987). */
  id: z.string().optional(),
  pid: z.number().int().positive().optional(),
  name: z.string().optional(),
  executable: z.string().optional(),
  commandLine: z.string().optional(),
  parent: z
    .object({
      pid: z.number().int().positive().optional(),
      name: z.string().optional(),
      executable: z.string().optional(),
    })
    .optional(),
});

const tlsJoinNoteSchema = z.enum([
  "records disagree",
  "disagrees with this record",
  "not among those read",
  "subject/issuer differ",
]);

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
      "authentication",
      "process",
      "network",
      "file",
      "registry",
      "service",
      "task",
      "email",
      "cloud",
      "memory",
      "other",
    ]),
    type: z.string().min(1),
    action: z.string().optional(),
    outcome: z.string().optional(),
  }),
  actor: canonicalEntitySchema.optional(),
  subject: canonicalEntitySchema.optional(),
  object: canonicalEntitySchema.optional(),
  target: canonicalEntitySchema.optional(),
  account: z
    .object({
      id: z.string().optional(),
      name: z.string().optional(),
      domain: z.string().optional(),
    })
    .optional(),
  authentication: z
    .object({
      sessionId: z.string().optional(),
      logonType: z.number().int().nonnegative().optional(),
      protocol: z.string().optional(),
      mechanism: z.string().optional(),
      // The credential the call was signed with (an AWS access key id, an Identity Center
      // credentialId) — a credential, not a session; and the identity that issued the session
      // (an AWS session issuer ARN). Both from #931 item 5.
      credentialId: z.string().optional(),
      issuer: z.string().optional(),
    })
    .optional(),
  session: z
    .object({
      id: z.string().optional(),
      terminal: z.string().optional(),
      interactive: z.boolean().optional(),
    })
    .optional(),
  network: z
    .object({
      source: z
        .object({
          address: z.string().optional(),
          port: z.number().int().positive().max(65535).optional(),
          hostname: z.string().optional(),
        })
        .optional(),
      destination: z
        .object({
          address: z.string().optional(),
          port: z.number().int().positive().max(65535).optional(),
          hostname: z.string().optional(),
        })
        .optional(),
      protocol: z.string().optional(),
    })
    .optional(),
  process: canonicalProcessSchema.optional(),
  tlsGraph: tlsGraphBlockSchema.optional(), // tlsGraphRows.ts, #997: cert/name/client-cert/JA3 node one sensor's upload showed
  entra: entraPathBlockSchema.optional(), // entraPrivilegePath.ts, #973; block in canonicalEntra.ts
  awsLineage: awsLineageBlockSchema.optional(), // awsLineage.ts, #979; block in canonicalAwsLineage.ts
  // Compute-lifecycle summary rows (#931 item 8; Azure/GCP are the second half, #1066).
  awsCompute: awsComputeBlockSchema.optional(),
  azureCompute: azureComputeBlockSchema.optional(),
  azureVmssCompute: azureVmssComputeBlockSchema.optional(),
  gcpCompute: gcpComputeBlockSchema.optional(),
  gcp: gcpBlockSchema.optional(), // gcpRow.ts, #931 item 12: identity, binding delta, credential fact, key step, workload attachment
  gcpServiceAccountJoin: gcpServiceAccountJoinBlockSchema.optional(), // gcpServiceAccountJoin.ts, #1065: per-service-account facts joined by id or email
  loggingChange: loggingChangeBlockSchema.optional(), // loggingChange.ts, #931 item 14; block in canonicalLogging.ts
  acquisitionCoverage: acquisitionCoverageBlockSchema.optional(), // kapeAcquisitionLog.ts, #932 item 1; block in canonicalAcquisition.ts
  diskImageAcquisition: diskImageAcquisitionSchema.optional(), // diskImageAcquisitionLog.ts, #1102; block in canonicalDiskImage.ts
  recoveredFragment: recoveredFragmentBlockSchema.optional(), // bulkExtractorUrlImport.ts, #932 item 4; block in canonicalRecoveredFragment.ts
  decodedString: decodedStringBlockSchema.optional(), // flossResultImport.ts, #932 item 5; block in canonicalDecodedString.ts
  capaMatch: capaMatchBlockSchema.optional(), // capaResultImport.ts, #932 item 6; block in canonicalCapaMatch.ts
  capaCompositeLead: capaCompositeLeadBlockSchema.optional(), // capaResultImport.ts, #932 item 6
  olevbaFinding: olevbaFindingBlockSchema.optional(), // olevbaResultImport.ts, #932 item 7
  sqliteRowState: sqliteRowStateBlockSchema.optional(), // sqliteRowStateImport.ts, #932 item 8
  olevbaStompingLead: olevbaStompingLeadBlockSchema.optional(), // olevbaResultImport.ts, #932 item 7
  olevbaCompoundLead: olevbaCompoundLeadBlockSchema.optional(), // olevbaResultImport.ts, #932 item 7
  mailboxChain: mailboxChainBlockSchema.optional(), // mailboxChain.ts, #975; block in canonicalMailbox.ts
  memoryRun: memoryRunBlockSchema.optional(), // memoryRunEnvelope.ts, #1016; block in canonicalMemoryRun.ts
  gwsLifecycle: gwsLifecycleBlockSchema.optional(), // gwsOAuthLifecycle.ts, #983; block in canonicalGwsLifecycle.ts
  driveSharing: driveSharingBlockSchema.optional(), // Drive sharing/access + Takeout (#931 item 11); blocks in canonicalGwsDrive.ts
  driveAccess: driveAccessBlockSchema.optional(),
  takeout: takeoutBlockSchema.optional(),
  takeoutLifecycle: takeoutLifecycleBlockSchema.optional(),
  driveExposure: driveExposureBlockSchema.optional(), // gwsDriveExposure.ts, #1064: sharing change joined to later access, by tenant + doc_id
  // A TLS record's own reading (tlsSession.ts, #933 item 6): SNI, protocol facts, cert, chain check, observer.
  tls: z
    .object({
      sni: z.string().optional(),
      version: z.string().optional(),
      cipher: z.string().optional(),
      curve: z.string().optional(),
      established: z.boolean().optional(),
      resumed: z.boolean().optional(),
      validation: z.string().optional(),
      sniMatchesCert: z.boolean().optional(),
      directionFlipped: z.boolean().optional(),
      ja3: z.string().optional(),
      ja3s: z.string().optional(),
      certificate: z
        .object({
          fingerprint: z.string().optional(),
          fingerprintAlg: z.enum(["sha1", "sha256"]).optional(),
          identity: z.string().optional(),
          subject: z.string().optional(),
          issuer: z.string().optional(),
          serial: z.string().optional(),
          names: z.array(z.string()).optional(),
          namesTotal: z.number().int().nonnegative().optional(),
          namesDigest: z.string().optional(),
          dnsNames: z.array(z.string()).optional(),
          dnsNamesTotal: z.number().int().nonnegative().optional(),
          notBefore: z.string().optional(),
          notAfter: z.string().optional(),
          ca: z.boolean().optional(),
          // The identity was filled from the upload's x509 record by FUID (tlsGraphJoin.ts, #997),
          // or why that join was not made.
          identityFrom: z.literal("x509 record").optional(),
          x509Join: tlsJoinNoteSchema.optional(),
        })
        .optional(),
      // On a certificate row: which side presented it (Zeek x509 client_cert / host_cert).
      certificateRole: z.enum(["client", "server"]).optional(),
      clientCertificate: z
        .object({
          subject: z.string().optional(),
          issuer: z.string().optional(),
          identity: z.string().optional(),
          fingerprint: z.string().optional(),
          fingerprintAlg: z.enum(["sha1", "sha256"]).optional(),
          serial: z.string().optional(),
          names: z.array(z.string()).optional(),
          namesTotal: z.number().int().nonnegative().optional(),
          namesDigest: z.string().optional(),
          dnsNames: z.array(z.string()).optional(),
          dnsNamesTotal: z.number().int().nonnegative().optional(),
          notBefore: z.string().optional(),
          notAfter: z.string().optional(),
          chainFuids: z.array(z.string()).optional(),
          identityFrom: z.literal("x509 record").optional(),
          x509Join: tlsJoinNoteSchema.optional(),
        })
        .optional(),
      observer: z.object({ name: z.string(), sourceField: z.string() }).optional(),
      locator: z
        .object({
          uid: z.string().optional(),
          id: z.string().optional(),
          certChainFuids: z.array(z.string()).optional(),
        })
        .optional(),
      records: z.number().int().positive(),
    })
    .optional(),
  // A macOS quarantine record (quarantineRecord.ts, #933 item 7) and its file-attribute join (quarantineJoin.ts, #1037); both blocks live in canonicalQuarantine.ts.
  quarantine: quarantineBlockSchema.optional(),
  quarantineAttribute: quarantineAttributeBlockSchema.optional(),
  // A Defender Operational record's own reading (defenderEvents.ts): disposition, threat, every
  // flagged resource. The block lives in canonicalDefender.ts; defenderEpisodes.ts reads it (#964).
  defender: defenderBlockSchema.optional(),
  // A LEAPP row's origin reading (mobileOriginRegistry.ts, #988): the facets its columns established, the registry coverage, the device / account the row names.
  mobile: mobileBlockSchema.optional(),
  // What the memory image says about itself (memoryImageFacts.ts, #933 item 12): kernel SystemTime
  // (never "captured at"), layer stack, dump kind/type, symbol table — from windows.info /
  // windows.crashinfo in the SAME upload only.
  image: z
    .object({
      systemTime: z.string().optional(),
      systemTimeRaw: z.string().optional(),
      dumpKind: z.string().optional(),
      dumpType: z.string().optional(),
      symbols: z.string().optional(),
      layers: z.array(z.string()),
    })
    .optional(),
  // A DNS record's reading — the endpoint's own records (dnsRecord.ts) or a sensor's view with
  // the leads one upload establishes (dnsWireRows.ts, #996); the block lives in canonicalDns.ts.
  dns: dnsBlockSchema.optional(),
  file: z
    .object({
      path: z.string().optional(),
      name: z.string().optional(),
      sha256: z.string().optional(),
      md5: z.string().optional(),
      // The rights a Security object-access record carries (objectAccess.ts, #930 item 7): the
      // mask as logged, the rights by bit, their classes, the object type and the handle.
      access: z
        .object({
          mask: z.string().optional(),
          rights: z.array(z.string()),
          classes: z.array(z.string()),
          objectType: z.string().optional(),
          handleId: z.string().optional(),
        })
        .optional(),
    })
    .optional(),
  // A web/transfer/SMB row as the sensor logged it (canonicalWeb.ts #993, canonicalSmb.ts #1085).
  web: webBlockSchema.optional(),
  transfer: transferBlockSchema.optional(),
  smb: smbBlockSchema.optional(),
  registry: z
    .object({
      key: z.string().optional(),
      valueName: z.string().optional(),
      valueData: z.string().optional(),
    })
    .optional(),
  service: z
    .object({
      name: z.string().optional(),
      displayName: z.string().optional(),
      executable: z.string().optional(),
    })
    .optional(),
  task: z
    .object({
      name: z.string().optional(),
      command: z.string().optional(),
    })
    .optional(),
  mailbox: z
    .object({
      messageId: z.string().optional(),
      sender: z.string().optional(),
      recipients: z.array(z.string()).optional(),
      cc: z.array(z.string()).optional(),
      subject: z.string().optional(),
      // What the headers INDICATE about delivery (#930 item 2) — an indication, never a fact.
      deliveryIndicated: z
        .array(z.object({ address: z.string(), by: z.enum(["delivered-to", "received-for"]) }))
        .optional(),
      // Every attachment with its OWN digest from the decoded part; the campaign scope matches on it.
      attachmentsNotRead: z.number().int().nonnegative().optional(),
      attachments: z
        .array(
          z.object({
            name: z.string(),
            contentType: z.string().optional(),
            size: z.number().int().nonnegative().optional(),
            sha256: z.string().optional(),
            md5: z.string().optional(),
            digestUnavailable: z.string().optional(),
          }),
        )
        .optional(),
    })
    .optional(),
  cloud: z
    .object({
      provider: z.string().optional(),
      principalId: z.string().optional(),
      principalType: z.string().optional(),
      tenant: z.string().optional(),
      accountId: z.string().optional(),
      // The account the record was DELIVERED to (CloudTrail recipientAccountId). `accountId`
      // stays the caller's account; a cross-account action differs in the two (#931 item 5).
      recipientAccountId: z.string().optional(),
      region: z.string().optional(),
      resource: z.string().optional(),
    })
    .optional(),
  time: z.object({
    observed: z.string(),
    normalized: z.string(),
    timezone: z.string(),
    precision: z.enum(["date", "minute", "second", "millisecond", "microsecond", "unknown"]),
    clockConfidence: z.enum(["recorded", "inferred", "unknown"]),
  }),
  evidence: z.object({
    rawRecords: z.array(rawRecordPointerSchema).min(1),
    sourceArtifactHash: z
      .string()
      .regex(/^sha256:[a-f0-9]{64}$/)
      .optional(),
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
  // Which raw record a field came from when the envelope joins several (#993): a path prefix (`web.bodies.0`, `transfer.requests.1`) → that record's locator, which must be one of `evidence.rawRecords`. Every field under the prefix is attributed to it; the longest matching prefix wins; fields under no prefix keep the first record.
  locatorMap?: Record<string, string>;
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

// The records a normalized path is attributed to. An ANCESTOR entry (the longest `locatorMap`
// prefix naming the path, matched on whole segments) replaces the first record; a DESCENDANT
// entry (a prefix under the path — an array is one leaf, so `web.bodies.0.transfer` sits under
// the leaf `web.bodies`) is added to it: the leaf then rests on every record that fed it.
function locatorsFor(path: string, locatorMap: Record<string, string>, first: string): string[] {
  let best = "";
  const under: string[] = [];
  for (const prefix of Object.keys(locatorMap)) {
    if (path === prefix || path.startsWith(`${prefix}.`)) {
      if (prefix.length > best.length) best = prefix;
    } else if (prefix.startsWith(`${path}.`)) under.push(locatorMap[prefix]);
  }
  return [...new Set([best ? locatorMap[best] : first, ...under])];
}

export function createCanonicalEvent(input: CreateCanonicalEventInput): CanonicalEventEnvelope {
  const { rawFieldMap = {}, confidenceMap = {}, derivationMap = {}, locatorMap = {}, ...fields } = input;
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
  const known = new Set(input.evidence.rawRecords.map((r) => r.locator));
  for (const locator of Object.values(locatorMap)) {
    if (!known.has(locator))
      throw new Error(`locatorMap names a record not in evidence.rawRecords: ${locator}`);
  }
  const fieldProvenance: CanonicalEventEnvelope["fieldProvenance"] = {};
  for (const path of normalizedLeafPaths(base).filter(
    (path) => !path.startsWith("evidence.") && !path.startsWith("producer."),
  )) {
    const rawFields = rawFieldMap[path];
    const derivation = derivationMap[path];
    const recordLocators = locatorsFor(path, locatorMap, firstLocator);
    fieldProvenance[path] = rawFields?.length
      ? {
          origin: "raw",
          confidence: confidenceMap[path] ?? "high",
          rawFields: [...rawFields],
          recordLocators,
        }
      : {
          origin: "derived",
          confidence: confidenceMap[path] ?? "high",
          derivation:
            derivation ??
            `${input.producer.mappingVersion}: deterministic mapping from referenced raw record`,
          recordLocators,
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
    return parsed.error.issues.map((issue) => `${issue.path.join(".") || "canonical"}: ${issue.message}`);
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
      if (!rawLocators.has(locator))
        issues.push(`field provenance references an unknown record: ${path} -> ${locator}`);
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
  return events.map((event) =>
    event.canonical
      ? {
          ...event,
          canonical: {
            ...event.canonical,
            evidence: { ...event.canonical.evidence, sourceArtifactHash: hash },
          },
        }
      : { ...event },
  );
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
const LEGACY_ACCOUNT =
  /(?<![\\/:.\w])(NT AUTHORITY|NT SERVICE|Window Manager|Font Driver Host|[A-Za-z][A-Za-z0-9.-]{1,30})\\([A-Za-z0-9._$-]{2,40})(?![\\/\w])/g;

function legacyLogon(event: ForensicEvent): LegacyLogon | undefined {
  const marker = LEGACY_LOGON_MARKER.exec(event.description);
  if (!marker) return undefined;
  const separator = event.description.indexOf(" - ");
  if (separator !== -1 && marker.index > separator) return undefined;
  const rest = event.description.slice(marker.index + marker[0].length);
  const segment =
    rest
      .replace(/^ - /, "")
      .split(/ - (?=[A-Za-z]+=)| @ | \[/)[0]
      ?.trim() ?? "";
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
  const actor: CanonicalEntity | undefined = accountName ? { kind: "account", name: accountName } : undefined;
  const target: CanonicalEntity | undefined = event.asset ? { kind: "host", name: event.asset } : undefined;
  const process =
    event.processName || event.parentName || event.pid || event.commandLine
      ? {
          ...(event.pid ? { pid: event.pid } : {}),
          ...(event.processName ? { name: event.processName } : {}),
          ...(event.path ? { executable: event.path } : {}),
          ...(event.commandLine ? { commandLine: event.commandLine } : {}),
          ...(event.parentName ? { parent: { name: event.parentName } } : {}),
        }
      : undefined;
  const file =
    event.path || event.sha256 || event.md5
      ? {
          ...(event.path ? { path: event.path, name: fileName(event.path) } : {}),
          ...(event.sha256 ? { sha256: event.sha256 } : {}),
          ...(event.md5 ? { md5: event.md5 } : {}),
        }
      : undefined;
  const network =
    event.srcIp || event.dstIp || event.port
      ? {
          ...(event.srcIp ? { source: { address: event.srcIp } } : {}),
          ...(event.dstIp || event.port
            ? {
                destination: {
                  ...(event.dstIp ? { address: event.dstIp } : {}),
                  ...(event.port ? { port: event.port } : {}),
                },
              }
            : {}),
        }
      : undefined;
  return createCanonicalEvent({
    event: {
      category,
      type: logon
        ? "logon"
        : category === "process"
          ? "observation"
          : category === "network"
            ? "connection"
            : category === "file"
              ? "observation"
              : "event",
      ...(event.action ? { action: event.action } : {}),
      ...(logon ? { outcome: logon.outcome } : {}),
    },
    ...(actor ? { actor } : {}),
    ...(target ? { target } : {}),
    ...(accountName
      ? {
          account: {
            name: accountName,
            ...(accountName.includes("\\") ? { domain: accountName.split("\\")[0] } : {}),
          },
        }
      : {}),
    ...(logon
      ? {
          authentication: {
            ...(logon.sessionId ? { sessionId: logon.sessionId } : {}),
            ...(logon.logonType !== undefined ? { logonType: logon.logonType } : {}),
          },
          ...(logon.workstation ? { session: { terminal: logon.workstation } } : {}),
        }
      : {}),
    ...(network || logon?.sourceIp
      ? {
          network: {
            ...network,
            ...(logon?.sourceIp ? { source: { address: logon.sourceIp } } : {}),
          },
        }
      : {}),
    ...(process ? { process } : {}),
    ...(file ? { file } : {}),
    time: { observed: event.timestamp, normalized: event.timestamp },
    evidence: {
      rawRecords: [{ source: "legacy-forensic-event", locator: `event:${event.id}`, recordId: event.id }],
    },
    producer: {
      importer: LEGACY_UPGRADE_IMPORTER,
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
      ...(accountName
        ? {
            "actor.name":
              "legacy-event-to-canonical-v1: one-time guarded identity extraction from legacy display text",
            "account.name":
              "legacy-event-to-canonical-v1: one-time guarded identity extraction from legacy display text",
          }
        : {}),
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
