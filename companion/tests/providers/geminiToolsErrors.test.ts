// Gemini tool-request errors (fix round 1): which 400s downgrade to the one-step lookup, which are a
// transcript-binding failure, and which keep their existing kinds. Bodies are recorded vendor shapes.
import { describe, it, expect } from "vitest";
import { httpErrorKind, ProviderError } from "../../src/providers/provider.js";
import { ToolsUnsupportedError, TurnBindingError } from "../../src/providers/toolCalling.js";
import { isRetryableError } from "../../src/analysis/ai/retry.js";
import { errorResponse, geminiWith, req } from "./toolAdapterHelpers.js";

const gErr = (code: number, message: string, status: string) => ({ error: { code, message, status } });

async function errorOf(status: number, body: unknown, analyze = false): Promise<unknown> {
  const { provider } = geminiWith([errorResponse(status, body)]);
  const call = analyze
    ? provider.analyze({ systemPrompt: "s", userPrompt: "u", images: [] })
    : provider.converse(req());
  return call.catch((e: unknown) => e);
}

describe("Gemini tool rejection → ToolsUnsupportedError", () => {
  it.each([
    ["Function calling is not enabled for tunedModels/my-model-123", "INVALID_ARGUMENT"],
    ["Function calling is not enabled for models/gemma-3-27b-it", "INVALID_ARGUMENT"],
    ["Model name models/gemini-1.0-pro-vision does not support function calling API.", "INVALID_ARGUMENT"],
    [
      "Invalid JSON payload received. Unknown name \"additionalProperties\" at 'tools[0].function_declarations[0].parameters': Cannot find field.",
      "INVALID_ARGUMENT",
    ],
  ])("400 %s", async (message, status) => {
    const err = await errorOf(400, gErr(400, message, status));
    expect(err).toBeInstanceOf(ToolsUnsupportedError);
    expect(isRetryableError(err)).toBe(false);
  });

  it("analyze never raises it", async () => {
    const err = await errorOf(
      400,
      gErr(400, "Function calling is not enabled for models/x", "INVALID_ARGUMENT"),
      true,
    );
    expect(err).not.toBeInstanceOf(ToolsUnsupportedError);
  });
});

describe("Gemini signature / turn-order 400 → TurnBindingError (one-time hop fallback)", () => {
  it.each([
    "Function call is missing a thought_signature in functionCall parts. This is required for tools to work correctly, and missing thought_signature may lead to degraded model performance.",
    "Please ensure that function call turn comes immediately after a user turn or after a function response turn.",
    "Please ensure that the number of function response parts is equal to the number of function call parts of the function call turn.",
  ])("400 %s", async (message) => {
    const err = await errorOf(400, gErr(400, message, "INVALID_ARGUMENT"));
    expect(err).toBeInstanceOf(TurnBindingError);
    expect(err).not.toBeInstanceOf(ToolsUnsupportedError);
    expect(isRetryableError(err)).toBe(false);
  });
});

describe("Gemini auth, quota, context and region errors keep their kinds", () => {
  it.each([
    [400, gErr(400, "API key not valid. Please pass a valid API key.", "INVALID_ARGUMENT")],
    [
      403,
      gErr(
        403,
        "Method doesn't allow unregistered callers (callers without established identity). Please use API Key or other form of API consumer identity to call this API.",
        "PERMISSION_DENIED",
      ),
    ],
    [
      429,
      gErr(
        429,
        "You exceeded your current quota, please check your plan and billing details.",
        "RESOURCE_EXHAUSTED",
      ),
    ],
    [
      400,
      gErr(
        400,
        "The input token count (1200000) exceeds the maximum number of tokens allowed (1048576).",
        "INVALID_ARGUMENT",
      ),
    ],
    [400, gErr(400, "User location is not supported for the API use.", "FAILED_PRECONDITION")],
    [
      400,
      gErr(
        400,
        "User location is not supported for the API use without a billing account linked. Function calling is not enabled here.",
        "FAILED_PRECONDITION",
      ),
    ],
  ])("%i %j", async (status, body) => {
    const err = await errorOf(status, body);
    expect(err).toBeInstanceOf(ProviderError);
    expect(err).not.toBeInstanceOf(ToolsUnsupportedError);
    expect(err).not.toBeInstanceOf(TurnBindingError);
    expect((err as ProviderError).kind).toBe(httpErrorKind(status));
  });
});
