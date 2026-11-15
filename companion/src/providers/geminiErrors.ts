// Which Gemini tool-request errors downgrade to the one-step lookup (fix round 1, controller ruling).
//
// Recorded vendor bodies are `{"error":{"code":400,"message":…,"status":"INVALID_ARGUMENT"}}`.
//   - A model or declaration Gemini cannot call ("Function calling is not enabled for models/…",
//     "… does not support function calling API", an unknown field in function_declarations) →
//     ToolsUnsupportedError: the model is marked tool-less.
//   - A thought signature or the order of call and result turns ("missing a thought_signature",
//     "function call turn comes immediately after …", "number of function response parts …") →
//     TurnBindingError: a one-time fallback for this question.
//   - Auth, permission, quota, context-length and region bodies keep their existing kinds, even
//     when Gemini sends them as a 400 and whatever else the text says.
import { ToolsUnsupportedError, TurnBindingError } from "./toolCalling.js";

const KEEP_KIND =
  /api key not valid|api_key_invalid|permission_denied|unregistered callers|resource_exhausted|exceeded your current quota|exceeds the maximum number of tokens|input token count|user location is not supported|failed_precondition/i;
const TOOLS_UNSUPPORTED =
  /function calling is not enabled|does not support function calling|function calling is (not supported|unsupported)|function_declarations|functionDeclarations/i;
const TURN_BINDING =
  /thought_signature|thought signature|function call turns? comes? immediately after|number of function response parts/i;

/** An auth, permission, quota, context-length or region body: never a tool-mode fallback (F3). */
export const geminiKeepsKind = (status: number, body: string): boolean =>
  status === 400 && KEEP_KIND.test(body);

/** The error a tool request's failure should raise, or undefined to keep the ordinary ProviderError. */
export function geminiToolError(status: number, body: string, message: string): Error | undefined {
  if (status !== 400 || KEEP_KIND.test(body)) return undefined;
  if (TURN_BINDING.test(body)) return new TurnBindingError(message);
  if (TOOLS_UNSUPPORTED.test(body)) return new ToolsUnsupportedError(message);
  return undefined;
}
