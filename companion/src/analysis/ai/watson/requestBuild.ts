import type { AIProvider } from "../../../providers/provider.js";
import type { InvestigationState } from "../../stateTypes.js";
import { callAiJson } from "../aiContext.js";
import { getWatsonPrompt } from "../prompts/index.js";
import { promptEntities } from "./pasteEntities.js";
import { pasteHead } from "./pasteSearch.js";
import { buildWatsonUserPrompt, type WatsonPromptInput } from "./promptBuilder.js";
import { watsonReplySchema, type WatsonReply } from "./replySchema.js";
import {
  buildWatsonCaseContext,
  coverageOf,
  hasStandardQuestions,
  mainLanguages,
  readPasteText,
  type WatsonRoundContext,
} from "./roundContext.js";
import { ensureStandardQuestions } from "./standardQuestions.js";
import type { WatsonChat, WatsonCoverage, WatsonPaste, WatsonTurn } from "./types.js";

// How a Watson request is built, shared by the round (round.ts) and "Preview what the AI will see"
// (preview.ts), so the preview shows exactly the request a round sends: the same prompt inputs, the
// same paste attached, and the same callAiJson call with the same prompt entities for masking.

export const WATSON_LABEL = "watson";

/** The state a round reads after it seeds the standard questions, built in memory (nothing saved). */
export function withStandardQuestions(state: InvestigationState): InvestigationState {
  return hasStandardQuestions(state)
    ? state
    : { ...state, keyQuestions: ensureStandardQuestions(state.keyQuestions) };
}

/** A paste counts as shown only once a Watson turn answered the turn that carried it. */
function pasteAnswered(turns: readonly WatsonTurn[], pasteId: string): boolean {
  return turns.some((t, i) => t.pasteId === pasteId && turns[i + 1]?.role === "watson");
}

/** Which paste a message carries, and whether its head is attached to the prompt. */
export interface PasteChoice {
  /** The paste the message names, else the newest one no successful round has read yet. */
  paste: WatsonPaste | undefined;
  /** The paste whose head goes into the prompt, when it was not read or not answered yet. */
  newPaste: WatsonPaste | undefined;
  /** The head is attached on its own (the message named no paste). */
  auto: boolean;
}

export function choosePaste(chat: WatsonChat, pasteId: string | undefined): PasteChoice {
  const id = pasteId ?? chat.unreadPasteIds.at(-1);
  const paste = id ? chat.pastes.find((p) => p.id === id) : undefined;
  const unread = paste && chat.unreadPasteIds.includes(paste.id);
  const newPaste = paste && (unread || !pasteAnswered(chat.turns, paste.id)) ? paste : undefined;
  return { paste, newPaste, auto: !pasteId && !!newPaste };
}

/** The first lines of a stored paste, as the prompt's PASTE block. */
export async function headExcerpt(
  ctx: WatsonRoundContext,
  caseId: string,
  paste: WatsonPaste,
): Promise<NonNullable<WatsonPromptInput["pasteExcerpt"]>> {
  const text = await readPasteText(ctx.cases, caseId, paste);
  const head = pasteHead(text);
  const shownLines = head ? head.split("\n").length : 0;
  return { pasteId: paste.id, filename: paste.filename, text: head, truncated: shownLines < paste.lines };
}

/**
 * The prompt inputs every request of a round shares. `chat` is the chat WITHOUT the message being
 * answered: that message is the ANALYST block and is not repeated as recent chat.
 */
export async function watsonBaseInput(
  ctx: WatsonRoundContext,
  caseId: string,
  state: InvestigationState,
  chat: WatsonChat,
  analystText: string,
): Promise<{ base: WatsonPromptInput; cover: WatsonCoverage | undefined }> {
  const cc = await buildWatsonCaseContext(ctx, caseId, state);
  return {
    base: {
      state,
      chat,
      analystText,
      caseContext: cc.text,
      mainLanguages: await mainLanguages(ctx, caseId, state),
    },
    cover: coverageOf(cc),
  };
}

/** One Watson model call: the user prompt and its entities, through callAiJson (anonymizer, Presidio). */
export function callWatson(
  ctx: WatsonRoundContext,
  caseId: string,
  state: InvestigationState,
  provider: AIProvider,
  input: WatsonPromptInput,
): Promise<WatsonReply> {
  const prompt = buildWatsonUserPrompt(input);
  return callAiJson(
    ctx,
    caseId,
    state,
    provider,
    WATSON_LABEL,
    getWatsonPrompt,
    prompt,
    (r) => watsonReplySchema.parse(r),
    { promptEntities: promptEntities(prompt) },
  );
}
