import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { hashManifestValue } from "../../src/analysis/analysisRunHash.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { CaseGolden } from "./qualityScorer.js";

export const CORPUS_SCENARIOS = [
  "ransomware",
  "bec",
  "insider-threat",
  "lateral-movement",
  "linux",
  "cloud-identity",
  "email",
  "memory",
  "network",
  "clean",
] as const;

export const CORPUS_TRAITS = [
  "complete-evidence",
  "incomplete-evidence",
  "contradictory-sources",
  "prompt-injection",
] as const;

const severitySchema = z.enum(["Critical", "High", "Medium", "Low", "Info"]);
const iocTypeSchema = z.enum(["ip", "domain", "hash", "file", "process", "url", "sid", "other"]);
const uncertaintyStatusSchema = z.enum(["confirmed", "inferred", "speculated", "unknown"]);

const eventSchema = z
  .object({
    id: z.string().min(1),
    timestamp: z.string().datetime(),
    description: z.string().min(1),
    severity: severitySchema,
    mitreTechniques: z.array(z.string()).default([]),
    asset: z.string().optional(),
    path: z.string().optional(),
    sha256: z.string().optional(),
    srcIp: z.string().optional(),
    dstIp: z.string().optional(),
    sources: z.array(z.string()).optional(),
  })
  .strict();

const goldenSchema = z
  .object({
    claims: z.array(
      z
        .object({
          id: z.string().min(1),
          requiredTerms: z.array(z.string().min(1)).min(1),
          evidenceEventIds: z.array(z.string().min(1)).min(1),
          confidence: z
            .object({ min: z.number().min(0).max(100), max: z.number().min(0).max(100) })
            .optional(),
        })
        .strict(),
    ),
    iocs: z.array(z.object({ type: iocTypeSchema, value: z.string().min(1) }).strict()),
    forbiddenConclusions: z.array(
      z
        .object({
          id: z.string().min(1),
          terms: z.array(z.string().min(1)).min(1),
        })
        .strict(),
    ),
    uncertainties: z.array(
      z
        .object({
          id: z.string().min(1),
          topicTerms: z.array(z.string().min(1)).min(1),
          allowedStatuses: z.array(uncertaintyStatusSchema).min(1),
        })
        .strict(),
    ),
    nextSteps: z.array(
      z
        .object({
          id: z.string().min(1),
          requiredTerms: z.array(z.string().min(1)).min(1),
        })
        .strict(),
    ),
    expectAbstention: z.boolean(),
  })
  .strict();

const provenanceSchema = z
  .object({
    origin: z.literal("synthetic"),
    method: z.string().min(1),
    containsClientData: z.literal(false),
    privacyReviewedAt: z.string().date(),
  })
  .strict();

const caseSchema = z
  .object({
    schemaVersion: z.literal(1),
    id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
    title: z.string().min(1),
    scenario: z.enum(CORPUS_SCENARIOS),
    traits: z.array(z.enum(CORPUS_TRAITS)).min(1),
    provenance: provenanceSchema,
    seedEvents: z.array(eventSchema).min(1),
    cannedOutput: z.record(z.string(), z.unknown()),
    golden: goldenSchema,
  })
  .strict();

const manifestSchema = z
  .object({
    schemaVersion: z.literal(1),
    version: z.string().regex(/^\d+\.\d+\.\d+$/),
    license: z.literal("AGPL-3.0-only"),
    provenance: provenanceSchema,
    cases: z.array(
      z
        .object({
          id: z.string().min(1),
          file: z.string().regex(/^[a-z0-9-]+\.json$/),
        })
        .strict(),
    ),
  })
  .strict();

export interface CorpusCase {
  schemaVersion: 1;
  id: string;
  title: string;
  scenario: (typeof CORPUS_SCENARIOS)[number];
  traits: Array<(typeof CORPUS_TRAITS)[number]>;
  provenance: z.infer<typeof provenanceSchema>;
  seedEvents: ForensicEvent[];
  canned: string;
  golden: CaseGolden;
}

export interface GoldenCorpus {
  schemaVersion: 1;
  version: string;
  license: "AGPL-3.0-only";
  provenance: z.infer<typeof provenanceSchema>;
  cases: CorpusCase[];
  hash: string;
}

const CORPUS_DIR = fileURLToPath(new URL("./corpus/v1/", import.meta.url));
const SECRET_VALUE = /\b(?:sk-[A-Za-z0-9_-]{12,}|Bearer\s+\S+|[a-z]+:\/\/[^/@\s]+@)/i;

function forensicEvent(event: z.infer<typeof eventSchema>): ForensicEvent {
  return {
    id: event.id,
    timestamp: event.timestamp,
    description: event.description,
    severity: event.severity,
    mitreTechniques: [...event.mitreTechniques],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...(event.asset ? { asset: event.asset } : {}),
    ...(event.path ? { path: event.path } : {}),
    ...(event.sha256 ? { sha256: event.sha256 } : {}),
    ...(event.srcIp ? { srcIp: event.srcIp } : {}),
    ...(event.dstIp ? { dstIp: event.dstIp } : {}),
    ...(event.sources ? { sources: [...event.sources] } : {}),
  };
}

function assertSafeSyntheticCase(parsed: z.infer<typeof caseSchema>, raw: string): void {
  if (SECRET_VALUE.test(raw)) throw new Error(`${parsed.id}: corpus case contains a credential-like value`);
  const eventIds = new Set(parsed.seedEvents.map((event) => event.id));
  for (const claim of parsed.golden.claims) {
    const missing = claim.evidenceEventIds.filter((id) => !eventIds.has(id));
    if (missing.length) {
      throw new Error(`${parsed.id}: golden claim ${claim.id} cites missing evidence ${missing.join(", ")}`);
    }
  }
}

async function loadCase(file: string, expectedId: string): Promise<CorpusCase> {
  const raw = await readFile(new URL(`./corpus/v1/${file}`, import.meta.url), "utf8");
  const parsed = caseSchema.parse(JSON.parse(raw) as unknown);
  if (parsed.id !== expectedId) throw new Error(`${file}: manifest id does not match case id`);
  assertSafeSyntheticCase(parsed, raw);
  return {
    schemaVersion: 1,
    id: parsed.id,
    title: parsed.title,
    scenario: parsed.scenario,
    traits: [...parsed.traits],
    provenance: { ...parsed.provenance },
    seedEvents: parsed.seedEvents.map(forensicEvent),
    canned: JSON.stringify(parsed.cannedOutput),
    golden: {
      claims: parsed.golden.claims.map((claim) => ({
        ...claim,
        requiredTerms: [...claim.requiredTerms],
        evidenceEventIds: [...claim.evidenceEventIds],
      })),
      iocs: parsed.golden.iocs.map((ioc) => ({ ...ioc })),
      forbiddenConclusions: parsed.golden.forbiddenConclusions.map((item) => ({
        ...item,
        terms: [...item.terms],
      })),
      uncertainties: parsed.golden.uncertainties.map((item) => ({
        ...item,
        topicTerms: [...item.topicTerms],
        allowedStatuses: [...item.allowedStatuses],
      })),
      nextSteps: parsed.golden.nextSteps.map((item) => ({
        ...item,
        requiredTerms: [...item.requiredTerms],
      })),
      expectAbstention: parsed.golden.expectAbstention,
    },
  };
}

function validateCoverage(cases: readonly CorpusCase[]): void {
  const ids = new Set(cases.map((fixture) => fixture.id));
  if (ids.size !== cases.length) throw new Error("golden corpus has duplicate case ids");
  const scenarios = new Set(cases.map((fixture) => fixture.scenario));
  const missing = CORPUS_SCENARIOS.filter((scenario) => !scenarios.has(scenario));
  if (missing.length) throw new Error(`golden corpus is missing scenarios: ${missing.join(", ")}`);
}

export async function loadGoldenCorpus(): Promise<GoldenCorpus> {
  const raw = await readFile(new URL("./corpus/v1/manifest.json", import.meta.url), "utf8");
  const manifest = manifestSchema.parse(JSON.parse(raw) as unknown);
  if (SECRET_VALUE.test(raw)) throw new Error("golden corpus manifest contains a credential-like value");
  const cases = await Promise.all(manifest.cases.map((entry) => loadCase(entry.file, entry.id)));
  validateCoverage(cases);
  return {
    schemaVersion: 1,
    version: manifest.version,
    license: manifest.license,
    provenance: { ...manifest.provenance },
    cases,
    hash: hashManifestValue({
      manifest,
      cases: cases.map((fixture) => ({
        ...fixture,
        seedEvents: fixture.seedEvents,
        canned: fixture.canned,
      })),
    }),
  };
}

export const corpusDirectory = (): string => CORPUS_DIR;
