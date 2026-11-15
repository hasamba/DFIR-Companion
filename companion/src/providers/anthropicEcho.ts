// How an assistant turn goes back to the Anthropic Messages API on the next send.
//
// Vendor rule (platform.claude.com, "Prefix checks on thinking blocks"): a thinking block is bound
// to everything sent before it — `system`, `tools`, every earlier message, and earlier blocks of
// its own message. Change any of that and the block is invalid (a 400 on current models). Blocks
// must also never be moved.
//
// So the adapter keeps each reply's content array in its ORIGINAL order (`opaque.blocks`) together
// with a fingerprint of what was sent before it (`opaque.prefixHash`). On the next send:
//   - nothing earlier changed → the blocks go back byte-identical;
//   - the masked transcript changed at or before a block (Watson re-masks every send, D6) → that
//     thinking block and every later one in the turn is dropped. Text and tool_use still go, as the
//     caller gave them (masked). An unmasked value is never sent to keep a block valid. The vendor's
//     own guidance for removed sensitive text is the same: drop the thinking after the change.
// Later turns check their own fingerprint, which already records any drop made when they were
// produced, so a drop never leaves a gap in the chain of thinking blocks.
import { createHash } from "node:crypto";
import type { ToolCall, ToolTurn } from "./toolCalling.js";

export type AnthropicBlock = { type: string; [key: string]: unknown };

export interface AnthropicOpaque {
  p: "anthropic"; // only this adapter echoes it; another provider's opaque value is ignored
  v: 1;
  prefixHash: string;
  blocks: AnthropicBlock[];
}

export const TEXT_JOIN = "\n\n";

export function isThinkingBlock(b: AnthropicBlock): boolean {
  return b.type === "thinking" || b.type === "redacted_thinking";
}

// JSON with sorted keys, so the fingerprint follows content, not key order (the API compares parsed
// JSON too).
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

/**
 * Fingerprint of everything a new block would be bound to: system, tools and the messages so far.
 * `binding` adds the model and thinking settings, so a transcript carried to another model or
 * thinking mode drops the old thinking instead of sending it on.
 */
export function prefixFingerprint(
  binding: unknown,
  system: unknown,
  tools: unknown,
  messages: readonly unknown[],
): string {
  return createHash("sha256").update(canonical({ binding, system, tools, messages })).digest("hex");
}

/** The opaque value, when it is one this adapter wrote. Anything else is ignored. */
export function readOpaque(value: unknown): AnthropicOpaque | undefined {
  if (!value || typeof value !== "object") return undefined;
  const o = value as Partial<AnthropicOpaque>;
  if (o.p !== "anthropic" || o.v !== 1 || typeof o.prefixHash !== "string" || !Array.isArray(o.blocks))
    return undefined;
  const valid = o.blocks.every((b) => !!b && typeof b === "object" && typeof b.type === "string");
  return valid ? (o as AnthropicOpaque) : undefined;
}

export function toolUseBlock(c: ToolCall): AnthropicBlock {
  return { type: "tool_use", id: c.id, name: c.name, input: c.input };
}

type AssistantTurn = Extract<ToolTurn, { role: "assistant" }>;

function plainBlocks(turn: AssistantTurn): AnthropicBlock[] {
  const text: AnthropicBlock[] = turn.text ? [{ type: "text", text: turn.text }] : [];
  return [...text, ...turn.calls.map(toolUseBlock)];
}

function sameCall(b: AnthropicBlock, c: ToolCall): boolean {
  return b.name === c.name && canonical(b.input) === canonical(c.input);
}

/**
 * The content to send for one assistant turn. `prefixNow` is the fingerprint of what this request
 * sends before the turn. `withhold` names readable thinking the caller will not send.
 */
export function echoAssistantTurn(
  turn: AssistantTurn,
  prefixNow: string,
  withhold?: (text: string) => boolean,
): AnthropicBlock[] {
  const op = readOpaque(turn.opaque);
  if (!op) return plainBlocks(turn);
  const origText = op.blocks.filter((b) => b.type === "text").map((b) => String(b.text ?? ""));
  const textSame = origText.join(TEXT_JOIN) === turn.text;
  const calls = new Map(turn.calls.map((c) => [c.id, c]));
  const out: AnthropicBlock[] = [];
  let changed = op.prefixHash !== prefixNow;
  let textSent = false;
  if (!textSame && origText.length === 0) {
    // New text where the reply had none: it goes first, so every thinking block after it drops.
    changed = true;
    textSent = true;
    if (turn.text) out.push({ type: "text", text: turn.text });
  }
  for (const b of op.blocks) {
    if (isThinkingBlock(b)) {
      // A withheld block drops like a changed one: it and every later thinking block in the turn.
      if (!changed && b.type === "thinking" && withhold?.(String(b.thinking ?? ""))) changed = true;
      if (!changed) out.push(b);
    } else if (b.type === "text") {
      if (textSame) out.push(b);
      else {
        changed = true;
        if (!textSent && turn.text) out.push({ type: "text", text: turn.text });
        textSent = true;
      }
    } else if (b.type === "tool_use") {
      const c = calls.get(String(b.id));
      calls.delete(String(b.id));
      if (c && sameCall(b, c)) out.push(b);
      else {
        changed = true;
        if (c) out.push(toolUseBlock(c));
      }
    } else out.push(b);
  }
  return [...out, ...[...calls.values()].map(toolUseBlock)];
}
