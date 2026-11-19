import type { RouteContext } from "./context.js";

/**
 * Refuse a case the war-room bot must not serve: one that doesn't exist, or one behind a password
 * (a chat message carries no unlock — see routes/slashCommand.ts). Returns the message to send, or ""
 * when fine. Shared by the slash commands and the Telegram mirror's plain-text questions (#2647).
 */
export async function guardCase(ctx: RouteContext, caseId: string): Promise<string> {
  let meta;
  try {
    meta = await ctx.store.getCaseMeta(caseId);
  } catch {
    // Fail closed, exactly like the case-lock gate does on an unexpected metadata read failure.
    return `Case ${caseId} could not be read.`;
  }
  if (!meta) return `No such case: ${caseId}.`;
  if (meta.password)
    return `Case ${caseId} is password-protected and is not available over chat — use the dashboard.`;
  return "";
}
