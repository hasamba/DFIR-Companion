// Gemini generateContent mapping for one tool-calling turn: the request body built from a
// ConverseRequest, and the reply parts parsed into a ConverseResult.
//
// Vendor rules (aistudio.google.com/docs: function-calling and thought-signatures, generateContent):
//   - tools are `tools[{functionDeclarations}]`; the mode is toolConfig.functionCallingConfig AUTO |
//     NONE; results go back as `functionResponse` parts in one `role:"user"` content after the
//     model's turn, matched to calls by `id` when the model sent one.
//   - a `thoughtSignature` must go back "exactly as received", "in the exact part where it was
//     received". Gemini 3 puts one on the first functionCall part and may put one on a text part;
//     a missing call signature in the current turn is a 400. Changed history may use the documented
//     dummy signature `skip_thought_signature_validator` instead.
// So `opaque` keeps the reply's ORDERED part list, signatures included, with our call id for each
// call part. On the next send an unchanged part goes back byte-identical, in its place. A part whose
// masked text or arguments changed goes back as the caller gave it: never with its real signature
// (a call part gets the dummy one, a text part none). Signed parts are never joined or moved.
import type { ConverseRequest, ConverseResult, ToolCall, ToolResult, ToolTurn } from "./toolCalling.js";
import { canonical } from "./anthropicEcho.js";
import { uniqueIds } from "./openaiTools.js";
import { geminiSchema } from "./geminiSchema.js";

export const SKIP_SIGNATURE = "skip_thought_signature_validator";

export interface GeminiPart {
  text?: string;
  thought?: boolean;
  thoughtSignature?: string;
  functionCall?: { id?: string; name?: string; args?: Record<string, unknown> };
  [key: string]: unknown;
}

interface GeminiOpaque {
  p: "gemini"; // only this adapter echoes it; another provider's opaque value is ignored
  v: 1;
  model: string;
  parts: GeminiPart[];
  ids: (string | null)[]; // our call id for each functionCall part, aligned with `parts`
}

type AssistantTurn = Extract<ToolTurn, { role: "assistant" }>;
// Our call id → the id the wire knows it by (undefined: the model sent none, so none goes back).
type WireIds = Map<string, string | undefined>;

const isAnswerText = (p: GeminiPart) => typeof p.text === "string" && p.thought !== true;
const isThought = (p: GeminiPart) => p.thought === true && typeof p.text === "string" && p.text !== "";

function readOpaque(value: unknown, model: string): GeminiOpaque | undefined {
  if (!value || typeof value !== "object") return undefined;
  const o = value as Partial<GeminiOpaque>;
  const ok =
    o.p === "gemini" &&
    o.v === 1 &&
    o.model === model &&
    Array.isArray(o.parts) &&
    Array.isArray(o.ids) &&
    o.ids.length === o.parts.length &&
    o.parts.every((p) => !!p && typeof p === "object");
  return ok ? (o as GeminiOpaque) : undefined;
}

function callPart(c: ToolCall, wireId: string | undefined, signature?: string): GeminiPart {
  return {
    functionCall: { ...(wireId ? { id: wireId } : {}), name: c.name, args: c.input },
    ...(signature ? { thoughtSignature: signature } : {}),
  };
}

// A turn with no usable opaque value: the masked text, then each call. The first call carries the
// dummy signature, since Gemini 3 rejects a current-turn call without one. Only a vendor id ever goes
// on the wire; our own ids (g<n>, #2 suffixes) never do, so these calls and results carry none and
// the results follow call order.
function plainParts(turn: AssistantTurn, wire: WireIds): GeminiPart[] {
  turn.calls.forEach((c) => wire.set(c.id, undefined));
  const text: GeminiPart[] = turn.text ? [{ text: turn.text }] : [];
  return [...text, ...turn.calls.map((c, i) => callPart(c, undefined, i === 0 ? SKIP_SIGNATURE : undefined))];
}

function sameCall(p: GeminiPart, c: ToolCall): boolean {
  return p.functionCall?.name === c.name && canonical(p.functionCall?.args ?? {}) === canonical(c.input);
}

/** The parts to send for one model turn, and the wire id of each of its calls. */
export function echoModelTurn(
  turn: AssistantTurn,
  model: string,
  wire: WireIds,
  withhold?: (text: string) => boolean,
): GeminiPart[] {
  const op = readOpaque(turn.opaque, model);
  if (!op) return plainParts(turn, wire);
  const origText = op.parts
    .filter(isAnswerText)
    .map((p) => p.text)
    .join("");
  const textSame = origText === turn.text;
  const calls = new Map(turn.calls.map((c) => [c.id, c]));
  const out: GeminiPart[] = [];
  let textSent = !textSame && origText === "" && !!turn.text;
  if (textSent) out.push({ text: turn.text });
  let needSig = false; // a dropped signed call: the next call sent carries the dummy signature
  op.parts.forEach((p, i) => {
    if (isAnswerText(p)) {
      if (textSame) out.push(p);
      else if (!textSent) {
        textSent = true;
        if (turn.text) out.push({ text: turn.text });
      }
    } else if (p.functionCall) {
      const id = op.ids[i];
      const c = id ? calls.get(id) : undefined;
      if (id) calls.delete(id);
      if (!c) {
        needSig = needSig || !!p.thoughtSignature;
        return;
      }
      wire.set(c.id, p.functionCall.id);
      const signed = needSig || !!p.thoughtSignature;
      if (sameCall(p, c))
        out.push(needSig && !p.thoughtSignature ? { ...p, thoughtSignature: SKIP_SIGNATURE } : p);
      else out.push(callPart(c, p.functionCall.id, signed ? SKIP_SIGNATURE : undefined));
      needSig = false;
    } else if (isThought(p) && withhold?.(p.text as string)) {
      needSig = needSig || !!p.thoughtSignature; // a withheld thought drops like a changed part
    } else out.push(p);
  });
  const extra = [...calls.values()];
  extra.forEach((c) => wire.set(c.id, undefined));
  return [
    ...out,
    ...extra.map((c, i) => callPart(c, undefined, needSig && i === 0 ? SKIP_SIGNATURE : undefined)),
  ];
}

// All results of one turn in one user content, in the order the calls were made (FC1, FC2, FR1, FR2).
function responseParts(results: ToolResult[], wire: WireIds): GeminiPart[] {
  const order = [...wire.keys()];
  const rank = (id: string) => (order.includes(id) ? order.indexOf(id) : order.length);
  return [...results]
    .sort((a, b) => rank(a.id) - rank(b.id))
    .map((r) => {
      const wireId = wire.has(r.id) ? wire.get(r.id) : r.id;
      return {
        functionResponse: {
          ...(wireId ? { id: wireId } : {}),
          name: r.name,
          response: r.isError ? { error: r.content } : { output: r.content },
        },
      };
    });
}

/** The readable thought text a built body echoes: what converse() would send, after every drop. */
export function geminiEchoedText(body: Record<string, unknown>): string[] {
  const contents = (body.contents ?? []) as Array<{ role: string; parts: GeminiPart[] }>;
  return contents
    .filter((c) => c.role === "model")
    .flatMap((c) => c.parts.filter(isThought).map((p) => p.text as string));
}

/**
 * The request body. No responseMimeType: JSON mode with function calling is preview-only on
 * Gemini 3+, so the prompt asks for JSON instead. The system prompt is folded into the first user
 * text, as analyze does.
 */
export function geminiToolBody(
  req: ConverseRequest,
  model: string,
  maxTokens?: number,
): Record<string, unknown> {
  const contents: unknown[] = [
    { role: "user", parts: [{ text: `${req.systemPrompt}\n\n${req.userPrompt}` }] },
  ];
  let wire: WireIds = new Map();
  for (const turn of req.transcript) {
    if (turn.role === "assistant") {
      wire = new Map();
      contents.push({ role: "model", parts: echoModelTurn(turn, model, wire, req.withhold) });
    } else contents.push({ role: "user", parts: responseParts(turn.results, wire) });
  }
  const functionDeclarations = req.tools.map((t) => ({
    name: t.name,
    description: t.description,
    parameters: geminiSchema(t.parameters),
  }));
  return {
    contents,
    tools: [{ functionDeclarations }],
    toolConfig: { functionCallingConfig: { mode: req.toolChoice === "none" ? "NONE" : "AUTO" } },
    ...(maxTokens ? { generationConfig: { maxOutputTokens: maxTokens } } : {}),
  };
}

function plainArgs(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

/**
 * The reply parts as tool calls or final text. A vendor call id is kept (a repeat gets `#n`); a
 * reply without ids gets `g<index>`. Thought-summary parts are readable reasoning (opaqueText).
 */
export function parseGeminiTurn(raw: unknown[], model: string, salt?: string): Omit<ConverseResult, "usage"> {
  const parts = raw.filter((p): p is GeminiPart => !!p && typeof p === "object");
  const callParts = parts.filter((p) => p.functionCall);
  const { ids } = uniqueIds(
    callParts.map((p) => p.functionCall?.id),
    "g",
    salt,
  );
  const calls: ToolCall[] = callParts.map((p, i) => ({
    id: ids[i],
    name: String(p.functionCall?.name ?? ""),
    input: plainArgs(p.functionCall?.args),
  }));
  let k = 0;
  const aligned = parts.map((p) => (p.functionCall ? ids[k++] : null));
  const text = parts
    .filter(isAnswerText)
    .map((p) => p.text)
    .join("");
  const opaqueText = parts
    .filter((p) => p.thought === true && typeof p.text === "string" && p.text)
    .map((p) => p.text as string);
  const opaque: GeminiOpaque | undefined = parts.length
    ? { p: "gemini", v: 1, model, parts, ids: aligned }
    : undefined;
  return { text, calls, ...(opaque ? { opaque } : {}), ...(opaqueText.length ? { opaqueText } : {}) };
}
