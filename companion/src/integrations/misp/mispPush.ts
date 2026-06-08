// Orchestrates a full Companion → MISP push. Find-or-create the MISP event by the case's
// idempotency tag (`dfir-companion:case-{id}`), then push IOCs as attributes and MITRE
// techniques from findings as tags. Idempotent: re-pushing skips attributes already present
// in the event (deduplicated by value) and creates the event only once.
//
// The client is injected as a structural interface so this is unit-testable with a mock (no
// network), matching the IRIS/Timesketch push pattern.

import type { InvestigationState, IOC } from "../../analysis/stateTypes.js";
import type { MispPushClientLike, MispEventCreate, MispAttrBody } from "./mispPushClient.js";

export interface MispPushInput {
  caseId: string;              // Companion case id — used for idempotency tag and event title
  state: InvestigationState;
}

export interface MispPushOptions {
  distribution?: string;       // MISP distribution: "0"=org (default), "1"=community, "2"=connected, "3"=all
  analysis?: string;           // MISP analysis: "0"=initial, "1"=ongoing (default), "2"=complete
  baseUrl?: string;            // to build a clickable event URL in the result
}

export interface MispPushResult {
  eventId: string;
  eventInfo: string;
  created: boolean;            // true = the event was newly created
  attributes: { added: number; existing: number; skipped: number };
  tags: number;                // MITRE + idempotency tags attached
  eventUrl?: string;
  warnings: string[];
}

const COMPANION_TAG_PREFIX = "dfir-companion:case-";

// Derive the worst severity across all findings → MISP threat_level_id.
// MISP: 1=High, 2=Medium, 3=Low, 4=Undefined.
function worstThreatLevel(state: InvestigationState): string {
  for (const sev of ["Critical", "High", "Medium", "Low"]) {
    if (state.findings.some((f) => f.severity === sev)) {
      if (sev === "Critical" || sev === "High") return "1";
      if (sev === "Medium") return "2";
      return "3"; // Low
    }
  }
  return "4"; // Undefined (no findings, or Info-only)
}

// Map a Companion IOC type to a MISP attribute type + category. Returns null for unmappable types.
function mapIocType(ioc: IOC): { type: string; category: string } | null {
  switch (ioc.type) {
    case "ip":      return { type: "ip-dst",   category: "Network activity" };
    case "domain":  return { type: "domain",   category: "Network activity" };
    case "url":     return { type: "url",      category: "External analysis" };
    case "file":    return { type: "filename", category: "Payload delivery" };
    case "process": return { type: "filename", category: "Artifacts dropped" };
    case "hash": {
      const len = ioc.value.replace(/\s/g, "").length;
      if (len === 32) return { type: "md5",    category: "Payload delivery" };
      if (len === 40) return { type: "sha1",   category: "Payload delivery" };
      if (len === 64) return { type: "sha256", category: "Payload delivery" };
      return { type: "md5", category: "Payload delivery" }; // best guess for unknown hash length
    }
    default: return null; // "other" — no reliable MISP type
  }
}

// Collect unique MITRE technique IDs from all findings.
function collectMitre(state: InvestigationState): string[] {
  const seen = new Set<string>();
  for (const f of state.findings) for (const t of f.mitreTechniques) seen.add(t);
  return [...seen];
}

export async function pushCaseToMisp(
  client: MispPushClientLike,
  input: MispPushInput,
  options: MispPushOptions = {},
): Promise<MispPushResult> {
  const warnings: string[] = [];
  const attributes = { added: 0, existing: 0, skipped: 0 };
  let tags = 0;

  // 1. Connectivity / auth (fatal — nothing works without this).
  await client.ping();

  // 2. Find-or-create the MISP event via the idempotency tag.
  const caseTag = `${COMPANION_TAG_PREFIX}${input.caseId}`;
  let eventId = await client.findEventByTag(caseTag);
  let created = false;
  const eventInfo = `DFIR Companion: ${input.caseId}`;

  if (!eventId) {
    const date = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const body: MispEventCreate = {
      info: eventInfo,
      threat_level_id: worstThreatLevel(input.state),
      analysis: options.analysis ?? "1",           // ongoing
      distribution: options.distribution ?? "0",   // org only (OPSEC-safe default)
      date,
    };
    eventId = await client.createEvent(body);
    created = true;
    // Tag with the idempotency tag so subsequent pushes find this event.
    try {
      await client.addTagToEvent(eventId, caseTag);
      tags += 1;
    } catch (err) {
      warnings.push(`case tag: ${(err as Error).message}`);
    }
  }

  // 3. List existing attributes for dedupe (non-fatal — a listing failure is recoverable;
  //    the worst outcome is duplicate attributes on re-push, flagged via a warning).
  const existingValues = new Set<string>();
  try {
    for (const a of await client.listAttributes(eventId)) {
      existingValues.add(a.value.trim().toLowerCase());
    }
  } catch (err) {
    warnings.push(`list attributes: ${(err as Error).message} — a re-push may add duplicate attributes`);
  }

  // 4. Push IOCs as MISP attributes.
  for (const ioc of input.state.iocs) {
    const mapped = mapIocType(ioc);
    if (!mapped) {
      attributes.skipped += 1;
      warnings.push(`ioc skipped (no MISP type for "${ioc.type}"): ${ioc.value}`);
      continue;
    }
    const key = ioc.value.trim().toLowerCase();
    if (existingValues.has(key)) { attributes.existing += 1; continue; }
    const body: MispAttrBody = {
      type: mapped.type,
      value: ioc.value,
      category: mapped.category,
      to_ids: ioc.type === "ip" || ioc.type === "domain" || ioc.type === "hash" || ioc.type === "url",
    };
    try {
      await client.addAttribute(eventId, body);
      existingValues.add(key);
      attributes.added += 1;
    } catch (err) {
      attributes.skipped += 1;
      warnings.push(`ioc "${ioc.value}": ${(err as Error).message}`);
    }
  }

  // 5. Attach MITRE technique tags (non-fatal — MISP may reject unknown tags gracefully).
  for (const tech of collectMitre(input.state)) {
    try {
      await client.addTagToEvent(eventId, `mitre-attack:${tech}`);
      tags += 1;
    } catch {
      // Silently skip: the tag may not be defined in this MISP instance.
    }
  }

  return {
    eventId,
    eventInfo,
    created,
    attributes,
    tags,
    eventUrl: options.baseUrl
      ? `${options.baseUrl.replace(/\/+$/, "")}/events/view/${eventId}`
      : undefined,
    warnings,
  };
}
