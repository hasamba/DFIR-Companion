// Launches running in THIS process. A `launching` proposal not in here is stranded (the server
// stopped mid-launch, or the save after the call failed): the boot sweep and the resolve route may
// treat it as uncertain. One in here is still waiting on Velociraptor and must not be touched.

const inFlight = new Set<string>();
const key = (caseId: string, proposalId: string): string => `${caseId}\u0000${proposalId}`;

export function markInFlight(caseId: string, proposalId: string): void {
  inFlight.add(key(caseId, proposalId));
}

export function clearInFlight(caseId: string, proposalId: string): void {
  inFlight.delete(key(caseId, proposalId));
}

export function isInFlight(caseId: string, proposalId: string): boolean {
  return inFlight.has(key(caseId, proposalId));
}
