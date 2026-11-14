import { MAX_VQL_BYTES } from "../../../vqlInput.js";
import { ALLOWED_ARTIFACTS, ALLOWED_CALLS, ALLOWED_ACCESSORS, WMI_CLASSES } from "./vqlAllowlist.js";

// The VELOCIRAPTOR block's fixed text (the host list is added by promptBuilder.ts, which defangs it).
// Generated from the allowlist constants so the prompt can never name a call the check refuses, and
// teaches the practical rules of the check (vqlAllowed.ts): without them most VQL is blocked.

/** Hostnames listed in the prompt; the block also states how many the case has. */
export const WATSON_VELO_HOSTS_MAX = 50;

export function veloRulesText(): string {
  return [
    "You may ask to run VQL on this case's Velociraptor server: set 'request' to",
    '{ "kind": "velociraptor", "mode": "collection" or "hunt", "hostname": "(collection only)", "title": "...", "vql": "...", "why": "..." }.',
    "The analyst approves it first. Rules:",
    '- Prefer a single-host collection (mode "collection", one hostname from the list below) when one host matters.',
    '  Use a fleet hunt (mode "hunt", no hostname) only when the question spans hosts. Never repeat a hunt that already ran.',
    "- Read-only only: never use anything that changes an endpoint, runs a program, or sends data out. A request that",
    "  breaks the rules below is blocked, not proposed. The VQL is at most " + MAX_VQL_BYTES + " bytes.",
    "- Every argument is name=value (no positional arguments).",
    "- A LET name that you call as a function must be CamelCase (contain a capital letter) and must not equal a built-in.",
    "- Paths use forward slashes: no '//', no doubled backslashes, no network paths, no URLs.",
    "- Path and artifact arguments must be plain quoted literals: no format(), no +, no variables.",
    "- if(then=...) and query= take a {...} subquery, never a string.",
    "- Allowed plugins and functions: " + ALLOWED_CALLS.join(", ") + ".",
    "- Allowed artifacts, called as Artifact.<Name>(...): " + ALLOWED_ARTIFACTS.join(", ") + ".",
    "- accessor= may only be one of: " + ALLOWED_ACCESSORS.join(", ") + ".",
    "- wmi() takes one literal SELECT query on these classes only: " + WMI_CLASSES.join(", ") + ".",
  ].join("\n");
}
