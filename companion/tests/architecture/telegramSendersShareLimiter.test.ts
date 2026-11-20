import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

// #2711: every Telegram message this process sends goes through the bot's ONE shared limiter
// (analysis/notify/telegramRateLimiter.ts). Each sender takes the limiter as an optional argument, so
// unit tests stay timing-free — which also means a call site that forgets to pass it compiles, passes
// every unit test, and quietly shares nothing. This test reads the source and fails on that.
//
// The behaviour itself (an alert goes before the mirror's backlog, a 429 pauses every sender) is
// proven end to end in tests/integrations/telegram/sharedTelegramLimiter.test.ts.

const SRC = join(__dirname, "..", "..", "src");

function sources(dir = SRC): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((d) => {
    const p = join(dir, d.name);
    if (d.isDirectory()) return sources(p);
    return d.name.endsWith(".ts") ? [p] : [];
  });
}

const rel = (p: string) => relative(SRC, p).split(sep).join("/");
const read = (file: string) => readFileSync(join(SRC, file), "utf8");
const all = sources().map((p) => ({ file: rel(p), text: readFileSync(p, "utf8") }));

/** The text of every call `name(...)` from its opening parenthesis to the matching close. */
function calls(text: string, name: string): string[] {
  const out: string[] = [];
  const re = new RegExp(`(?<![\\w.])${name}\\(`, "g");
  for (let m = re.exec(text); m; m = re.exec(text)) {
    let depth = 0;
    let i = m.index + name.length;
    for (; i < text.length; i++) {
      if (text[i] === "(") depth++;
      else if (text[i] === ")" && --depth === 0) break;
    }
    out.push(text.slice(m.index, i + 1));
  }
  return out;
}

describe("Telegram senders share the bot's limiter (#2711)", () => {
  it("only the three known senders build a Bot API sendMessage request", () => {
    const building = all
      .filter(({ text }) => /\/sendMessage`|"sendMessage"\)/.test(text))
      .map(({ file }) => file)
      .sort();
    expect(building).toEqual([
      "analysis/telegramPoller.ts", // sendTelegramMessage: command replies
      "integrations/notify/notifyDispatch.ts", // alerts
      "integrations/telegram/watsonMirrorSender.ts", // the Watson mirror (+ "Mirroring started")
    ]);
  });

  it("every sendTelegramMessage call passes the shared limiters", () => {
    const missing = all.flatMap(({ file, text }) =>
      calls(text, "sendTelegramMessage")
        .filter((c) => !c.includes("limiters: sharedTelegramLimiters"))
        .map((c) => `${file}: ${c.slice(0, 80)}`),
    );
    // The definition itself is `sendTelegramMessage(input: {...})`.
    expect(missing.filter((m) => !m.includes("sendTelegramMessage(input:"))).toEqual([]);
  });

  it("sendMirrorMessage is called only where a slot is taken first", () => {
    const callers = all
      .filter(({ text }) => calls(text, "sendMirrorMessage").length > 0)
      .map(({ file }) => file)
      .filter((f) => f !== "integrations/telegram/watsonMirrorSender.ts")
      .sort();
    expect(callers).toEqual(["composition/watsonMirrorWiring.ts", "routes/watsonMirrorCommand.ts"]);
    const command = read("routes/watsonMirrorCommand.ts");
    expect(command.indexOf("acquireAndCommit(")).toBeGreaterThan(-1);
    expect(command.indexOf("acquireAndCommit(")).toBeLessThan(command.indexOf("sendMirrorMessage({"));
    expect(command).toContain("sharedTelegramLimiters.forToken(");
  });

  it("the production notifier and the Watson mirror are handed the shared limiter", () => {
    expect(read("composition/runtimeStores.ts")).toContain("telegramLimiters: sharedTelegramLimiters");
    const wiring = read("composition/watsonMirrorWiring.ts");
    expect(wiring).toContain("limiter: sharedMirrorGate");
    expect(wiring).toMatch(/sharedMirrorGate[\s\S]*sharedTelegramLimiters\.forToken\(/);
  });
});
