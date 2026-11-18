// #2658: the user prompt as content blocks, with a cache breakpoint after its stable leading part.
// `cachePrefix` reaches a provider only as text userPrompt starts with, set by the masking gate: masked
// when anonymization is on, clear when it is off (#2675). Anything else sends the prompt as one block.

export type CacheControl = { type: "ephemeral"; ttl?: "1h" };

export interface TextBlock {
  type: "text";
  text: string;
  cache_control?: CacheControl;
}

export function cachedUserContent(
  userPrompt: string,
  cachePrefix: string | undefined,
  cacheControl: CacheControl,
): TextBlock[] {
  if (!cachePrefix || cachePrefix.length >= userPrompt.length || !userPrompt.startsWith(cachePrefix))
    return [{ type: "text", text: userPrompt }];
  return [
    { type: "text", text: cachePrefix, cache_control: cacheControl },
    { type: "text", text: userPrompt.slice(cachePrefix.length) },
  ];
}

/** Anthropic API: the default 5-minute breakpoint, refreshed by every hit. */
export const API_CACHE: CacheControl = { type: "ephemeral" };
/**
 * Claude Code CLI: its own later blocks are marked one hour, and the API rejects a 5-minute block
 * before a 1-hour one, so this block must be one hour too (probed 2026-11-17, claude 2.1.326).
 */
export const CLI_CACHE: CacheControl = { type: "ephemeral", ttl: "1h" };
