import { ARTIFACT_RE } from "./artifactRefs.js";
import type { VelociraptorRunResult } from "./velociraptorApi.js";

// Velociraptor's Client Monitoring table — the server-side list of CLIENT_EVENT artifacts every
// enrolled client runs continuously (#1409). A live monitor only READS a client's monitoring result
// set, so an artifact that is not in this table produces nothing, forever, while the monitor still
// looks healthy (an empty poll is not an error). Starting a monitor therefore has to put the artifact
// in the table, and the analyst has to be told when it is not there. Both go through the two VQL
// functions Velociraptor ships for this (`add_client_monitoring` / `rm_client_monitoring`, present
// since 0.6.x); the table is re-read afterwards so "it worked" means the table says so, not the call.
//
// Client monitoring is scoped by LABEL, not by client, and the default group is "all" — so enabling
// an artifact for a single-client monitor still enables it fleet-wide. The dashboard says so.

// The slice of VelociraptorClient this module needs — kept minimal so the unit tests run against a
// stateful fake instead of a subprocess.
export interface ClientMonitoringTableClient {
  listMonitoredArtifacts(): Promise<string[]>;
  run(vql: string): Promise<VelociraptorRunResult>;
}

// Whether the companion put the artifact in the table ("added") or found it there ("present").
export type VeloTableEntry = "added" | "present";

function assertArtifactName(artifact: string): string {
  if (!ARTIFACT_RE.test(artifact)) throw new Error("invalid artifact name");
  return artifact;
}

// The add/rm calls. The artifact name is the only interpolated value and is charset-validated first,
// so it cannot close the VQL literal. No label → Velociraptor's "all clients" group.
export function enableClientMonitoringVql(artifact: string): string {
  return `SELECT add_client_monitoring(artifact='${assertArtifactName(artifact)}') AS Added FROM scope()`;
}

export function disableClientMonitoringVql(artifact: string): string {
  return `SELECT rm_client_monitoring(artifact='${assertArtifactName(artifact)}') AS Removed FROM scope()`;
}

export async function isClientMonitoringEnabled(
  client: ClientMonitoringTableClient,
  artifact: string,
): Promise<boolean> {
  return (await client.listMonitoredArtifacts()).includes(artifact);
}

// Make sure the artifact is in the table. Verifies by re-reading the table: the add call returns a
// NULL row and exits 0 when the API user lacks the permission or the artifact does not exist, so
// the call's own result proves nothing. Throws a plain-language error the route can hand straight
// to the analyst when the artifact is still missing afterwards.
export async function ensureClientMonitoring(
  client: ClientMonitoringTableClient,
  artifact: string,
): Promise<VeloTableEntry> {
  assertArtifactName(artifact);
  if (await isClientMonitoringEnabled(client, artifact)) return "present";
  await client.run(enableClientMonitoringVql(artifact));
  if (await isClientMonitoringEnabled(client, artifact)) return "added";
  throw new Error(
    `could not enable ${artifact} in Velociraptor → Client Monitoring (does the API user have ` +
      `SERVER_ADMIN, and does the artifact exist on the server?). Enable it in the Velociraptor ` +
      `GUI, then start the monitor again.`,
  );
}

// Take the artifact back out of the table. A no-op when it is not there, so a delete after someone
// already removed it in the GUI stays quiet.
export async function releaseClientMonitoring(
  client: ClientMonitoringTableClient,
  artifact: string,
): Promise<void> {
  assertArtifactName(artifact);
  if (!(await isClientMonitoringEnabled(client, artifact))) return;
  await client.run(disableClientMonitoringVql(artifact));
}
