// AI Agent Forensics (#2690): launch one run on an EXPLICIT list of endpoints (§13.4).
//
// Shape (builder's call, §12): one PAUSED hunt carrying the generated artifacts (+ the
// Windows.Triage.Targets preservation with the AICodingAgents rule, when the server has it), then
// hunt_add() for each chosen client. A paused hunt never schedules itself on any client, so an empty
// or partial selection can never widen to the fleet; hunt_add schedules exactly the clients named.
// Carrying the run as a hunt lets the existing hunt machinery (status poll, collect, evidence-first,
// the case's import lock) do the collecting. If NO client could be added the hunt is stopped and the
// launch fails; clients that could not be added are reported by name.
//
// Every artifact definition goes up in its own artifact_set program (aiAgentArtifact.ts keeps each
// under the Windows command-line cap); the hunt program only names them.

import type { AiAgentArtifactBundle } from "./aiAgentArtifact.js";
import { CLIENT_RE } from "./clientInventory.js";

export const TRIAGE_ARTIFACT = "Windows.Triage.Targets";
export const TRIAGE_RULE = "AICodingAgents";
const HUNT_RE = /^H\.[A-Za-z0-9]+$/;
export const AI_AGENT_HUNT_EXPIRY_SECONDS = 7 * 86_400;
/** Per-endpoint collection timeout: YARA over the agent scopes plus the triage copy (as Big Hogs). */
export const AI_AGENT_COLLECTION_TIMEOUT_SECONDS = 7200;

export interface AiAgentLaunchClient {
  runProgram(program: string): Promise<{ rows: unknown[]; reason: string }>;
  huntGuiUrlFor(huntId: string): string | undefined;
}

export interface AiAgentLaunchInput {
  bundle: AiAgentArtifactBundle;
  clientIds: string[];
  /** Run Windows.Triage.Targets/AICodingAgents for preservation (preflight decided it exists). */
  preserve: boolean;
  uploadMaxBytes: number;
  description: string;
  expirySeconds?: number;
}

export interface AiAgentLaunchResult {
  huntId: string;
  guiUrl?: string;
  artifacts: string[];
  added: string[];
  failed: { clientId: string; error: string }[];
}

export class AiAgentLaunchError extends Error {}

function setProgram(yaml: string): string {
  if (yaml.includes("'''")) throw new AiAgentLaunchError("artifact definition may not contain '''");
  return `LET def = '''${yaml}'''\nSELECT artifact_set(definition=def) AS Set FROM scope()`;
}

function vqlText(s: string): string {
  return s.replace(/[^A-Za-z0-9 .,:()_\-/]/g, "").slice(0, 200);
}

/** The hunt program: paused, named artifacts, the triage spec. Exported for the snapshot test. */
export function huntProgram(input: AiAgentLaunchInput, artifacts: string[]): string {
  const expires = Math.max(3600, Math.floor(input.expirySeconds ?? AI_AGENT_HUNT_EXPIRY_SECONDS));
  const list = artifacts.map((a) => `'${a}'`).join(", ");
  const spec = input.preserve
    ? `, spec=dict(\`${TRIAGE_ARTIFACT}\`=dict(${TRIAGE_RULE}='Y', MaxFileSize='${Math.floor(input.uploadMaxBytes)}'))`
    : "";
  return (
    `SELECT hunt(description='DFIR Companion: ${vqlText(input.description)}', artifacts=[${list}]${spec}, ` +
    `timeout=${AI_AGENT_COLLECTION_TIMEOUT_SECONDS}, pause=TRUE, expires=now() + ${expires}) AS Hunt FROM scope()`
  );
}

const PERMISSION_REFUSAL_RE = /permission|denied|not allowed|ARTIFACT_WRITER/i;

async function setArtifact(client: AiAgentLaunchClient, name: string, yaml: string): Promise<void> {
  const { rows, reason } = await client.runProgram(setProgram(yaml));
  const ok = rows.length > 0 && (rows[0] as { Set?: unknown }).Set != null;
  if (!ok) {
    // The permission hint only when Velociraptor gave no reason or a permission one: on any other
    // refusal (a bad name, bad YAML) it sends the analyst after the wrong fix.
    const permission = !reason.trim() || PERMISSION_REFUSAL_RE.test(reason);
    throw new AiAgentLaunchError(
      `Velociraptor refused artifact ${name}${reason ? `: ${reason}` : ""}` +
        (permission ? " (the API user needs ARTIFACT_WRITER)" : ""),
    );
  }
}

/** Launch the run. Throws AiAgentLaunchError when nothing could be scheduled. */
export async function launchAiAgentRun(
  client: AiAgentLaunchClient,
  input: AiAgentLaunchInput,
): Promise<AiAgentLaunchResult> {
  const ids = [...new Set(input.clientIds.map((c) => c.trim()).filter(Boolean))];
  if (ids.length === 0)
    throw new AiAgentLaunchError("pick at least one endpoint — a run never targets the fleet");
  const bad = ids.filter((c) => !CLIENT_RE.test(c));
  if (bad.length) throw new AiAgentLaunchError(`invalid Velociraptor client id(s): ${bad.join(", ")}`);
  for (const p of input.bundle.parts) await setArtifact(client, p.name, p.yaml);
  for (const a of input.bundle.artifacts) await setArtifact(client, a.name, a.yaml);
  const artifacts = [
    ...input.bundle.artifacts.map((a) => a.name),
    ...(input.preserve ? [TRIAGE_ARTIFACT] : []),
  ];
  const { rows, reason } = await client.runProgram(huntProgram(input, artifacts));
  const hunt = (rows[0] as { Hunt?: Record<string, unknown> } | undefined)?.Hunt ?? {};
  const huntId = String(hunt.HuntId ?? hunt.hunt_id ?? "");
  if (!HUNT_RE.test(huntId))
    throw new AiAgentLaunchError(
      `Velociraptor returned no hunt id${reason ? `: ${reason}` : ""} (the API user needs START_HUNT)`,
    );
  const added: string[] = [];
  const failed: { clientId: string; error: string }[] = [];
  for (const clientId of ids) {
    const res = await client
      .runProgram(`SELECT hunt_add(client_id='${clientId}', hunt_id='${huntId}') AS Added FROM scope()`)
      .catch((e: Error) => ({ rows: [] as unknown[], reason: e.message }));
    const ok = res.rows.length > 0 && (res.rows[0] as { Added?: unknown }).Added != null;
    if (ok) added.push(clientId);
    else failed.push({ clientId, error: res.reason || "hunt_add returned nothing" });
  }
  if (added.length === 0) {
    await client
      .runProgram(`SELECT hunt_update(hunt_id='${huntId}', state='stop') AS Stopped FROM scope()`)
      .catch(() => undefined);
    throw new AiAgentLaunchError(
      `no endpoint could be added to the run (${failed.map((f) => `${f.clientId}: ${f.error}`).join("; ")})`,
    );
  }
  return { huntId, guiUrl: client.huntGuiUrlFor(huntId), artifacts, added, failed };
}
