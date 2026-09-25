// Readable names for the model that actually served an AI call (#1601).
//
// The Claude Code CLI takes an alias ("sonnet") and serves a concrete model ("claude-sonnet-5").
// The jobs popover shows both, and the concrete id is easier to read as "Sonnet 5". This module
// only renames ids it recognises. Anything else — an OpenRouter vendor/model path, an OpenAI or
// Ollama id, a near-miss — is returned exactly as the provider reported it. Nothing is guessed.

// claude-<family>-<major>[-<minor>][-<yyyymmdd>]: claude-sonnet-5, claude-opus-5-5,
// claude-haiku-4-5-20251001, claude-sonnet-4-20250514.
const FAMILY_FIRST = /^claude-(opus|sonnet|haiku)-(\d{1,2})(?:-(\d{1,2}))?(?:-(\d{8}))?$/;
// claude-<major>[-<minor>]-<family>[-<yyyymmdd>]: claude-3-5-sonnet-20241022, claude-3-opus-20240229.
const VERSION_FIRST = /^claude-(\d{1,2})(?:-(\d{1,2}))?-(opus|sonnet|haiku)(?:-(\d{8}))?$/;

function familyName(family: string): string {
  return family.charAt(0).toUpperCase() + family.slice(1);
}

function versionText(major: string, minor: string | undefined): string {
  return minor === undefined ? major : `${major}.${minor}`;
}

/** "claude-opus-5-5" -> "Opus 5.5". An id this function does not know comes back unchanged. */
export function modelDisplayName(id: string): string {
  const familyFirst = FAMILY_FIRST.exec(id);
  if (familyFirst) {
    const [, family, major, minor] = familyFirst;
    return `${familyName(family)} ${versionText(major, minor)}`;
  }
  const versionFirst = VERSION_FIRST.exec(id);
  if (versionFirst) {
    const [, major, minor, family] = versionFirst;
    return `${familyName(family)} ${versionText(major, minor)}`;
  }
  return id;
}

/** The fields of a job row the label is built from. */
export interface ModelLabelInput {
  model?: string;
  servedModel?: string;
  terminal: boolean;
}

/**
 * The text the jobs popover shows for a job's model:
 *   - served:                        "sonnet → Sonnet 5"
 *   - not served yet, version known: "sonnet (last run: Sonnet 5)" — queued or running only
 *   - otherwise:                     "sonnet"
 * When the readable name is the alias itself (a provider that serves exactly what was asked for),
 * the arrow would say nothing, so the alias stands alone.
 */
export function jobModelLabel(job: ModelLabelInput, lastServed?: string): string | undefined {
  const alias = job.model;
  if (!alias) return undefined;
  if (job.servedModel) {
    const served = modelDisplayName(job.servedModel);
    return served === alias ? alias : `${alias} → ${served}`;
  }
  if (!job.terminal && lastServed) {
    const last = modelDisplayName(lastServed);
    return last === alias ? alias : `${alias} (last run: ${last})`;
  }
  return alias;
}
