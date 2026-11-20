import type { Finding, InvestigationState } from "./stateTypes.js";
import type { WatsonFindingVerdict } from "./watsonItemTypes.js";
import { deriveSemanticKey, nounPhrase } from "./semanticKey.js";

// Identifiers DERIVED from a finding's title — its semanticKey and a Watson verdict's match key —
// are lowercased, underscore-joined fragments of the raw words ("T1059:alice_corp_dc01"). The
// redactor tokenizes whole values (a host, an account, an address) in text, so it never recognizes
// those fragments and they reached the redacted package verbatim. Rather than teaching the redactor
// a new shape, the redacted export rebuilds each key from the ALREADY-REDACTED title: the key then
// holds only words that the redacted title itself shows, so it cannot carry anything the title does
// not. Pure; returns a new state and leaves the input alone.

const TECHNIQUE_PREFIX = /^(T\d{4}(?:\.\d{3})?):/;

function rekeyFinding(f: Finding): Finding {
  return f.semanticKey ? { ...f, semanticKey: deriveSemanticKey(f) } : f;
}

// A verdict key is `id:<finding id>` (an id the redactor already walked as a whole string),
// `key:<semanticKey>` or `title:<lowercased title>` — the last two are rebuilt from the verdict's
// own redacted title, keeping the ATT&CK technique prefix (an id, never case data).
function rekeyVerdict(v: WatsonFindingVerdict): WatsonFindingVerdict {
  const title = String(v.title ?? "");
  if (v.key.startsWith("key:")) {
    const tech = TECHNIQUE_PREFIX.exec(v.key.slice(4))?.[1];
    const phrase = nounPhrase(title);
    return { ...v, key: `key:${tech ? `${tech}:${phrase}` : phrase}` };
  }
  if (v.key.startsWith("title:")) return { ...v, key: `title:${title.trim().toLowerCase()}` };
  return v;
}

/** Rebuild title-derived keys in an already-redacted state, for the redacted case export. */
export function redactDerivedKeys(state: InvestigationState): InvestigationState {
  return {
    ...state,
    findings: (state.findings ?? []).map(rekeyFinding),
    ...(state.watsonFindingVerdicts
      ? { watsonFindingVerdicts: state.watsonFindingVerdicts.map(rekeyVerdict) }
      : {}),
  };
}
