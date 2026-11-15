import type { InvestigationState } from "../../stateTypes.js";
import type { WatsonPromptInput } from "./promptBuilder.js";
import { promptEntities } from "./pasteEntities.js";
import { veloHostNames } from "./requestBuild.js";
import type { WatsonReply } from "./replySchema.js";
import type { WatsonRoundContext } from "./roundContext.js";
import { mergeMaskRoster } from "./superRoster.js";
import { toolRequestParts } from "./toolLoop.js";
import type { WatsonChat } from "./types.js";

/**
 * The first request of a tool-mode round, for the AI preview: the same system prompt (with the tools
 * addendum), user prompt, tools and entities the loop's first send carries, through the same
 * converseRestored gate. The gate stops the preview there, so this never returns a reply.
 */
export async function previewToolRequest(
  ctx: WatsonRoundContext,
  caseId: string,
  state: InvestigationState,
  chat: WatsonChat,
  base: WatsonPromptInput,
  cap: number,
): Promise<WatsonReply> {
  const { system, userPrompt, tools } = toolRequestParts({
    ctx,
    base,
    head: undefined,
    reaction: false,
    cap,
  });
  const roster = mergeMaskRoster(chat.maskRoster, base.rawRoster);
  await ctx.converseRestored!(
    caseId,
    state,
    ctx.provider,
    {
      systemPrompt: system,
      userPrompt,
      transcript: [],
      tools,
      toolChoice: "auto",
      idSalt: "t0",
      promptEntities: promptEntities(userPrompt, [...veloHostNames(base), ...roster.hosts], roster.users),
    },
    { pairs: [] },
    "watson",
  );
  throw new Error("the AI preview did not stop at the gate");
}
