import { describe, it, expect, vi, afterEach } from "vitest";
import { askJev, type JevQuestion, type JevRequestConfig } from "../../src/analysis/ai/jev/jevClient.js";

// A distinctive non-secret. Several tests assert it never reaches a thrown message, which needs a
// string that is easy to search for — NOT one shaped like a real credential. The first version of
// this line used a full-length `sk-or-v1-` + 64 hex fixture and GitHub push protection rejected the
// push: the scanner matches the SHAPE, and a fixture of zeroes matches it exactly as well as a live
// key would. Keep any stand-in credential in this repo un-key-shaped.
const KEY = "jev-test-credential-not-a-real-key";

const CFG: JevRequestConfig = {
  baseUrl: "https://openrouter.ai/api/alpha/decisions",
  model: "typesafe/jev-1.13",
  apiKey: KEY,
  timeoutMs: 5_000,
  maxRetries: 1,
};

const QUESTIONS: Readonly<Record<string, JevQuestion>> = {
  severity: {
    type: "score",
    instructions: "How severe is this row?",
    criteria: ["Informational", "Low", "Medium", "High", "Critical"],
  },
  category: {
    type: "choice",
    instructions: "What kind of event is this?",
    criteria: { persistence: "Survives a reboot", benign_admin: null },
  },
  needs_analyst: {
    type: "noul",
    instructions: "Does a human analyst need to look at this?",
    criteria: { true: "Ambiguous or high impact", false: "Clearly routine" },
  },
};

const ANSWERS = {
  severity: {
    type: "score",
    score: 2.45, // probability-weighted: it lands BETWEEN Medium and High
    legend: { "0": "Informational", "1": "Low", "2": "Medium", "3": "High", "4": "Critical" },
    probabilities: { "0": 0.05, "1": 0.1, "2": 0.45, "3": 0.3, "4": 0.1 },
    confidence: 0.71,
  },
  category: {
    type: "choice",
    choice: "persistence",
    probabilities: { persistence: 0.88, benign_admin: 0.12 },
    confidence: 0.88,
  },
  needs_analyst: { type: "noul", noul: 0.82 },
};

const OPENROUTER_BODY = {
  id: "dec_01",
  model: "typesafe/jev-1.13",
  provider: "typesafe",
  answers: ANSWERS,
  usage: { cost: 0.0000312, input_tokens: 412, output_tokens: 18 },
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function okFetch(body: unknown = OPENROUTER_BODY): ReturnType<typeof vi.fn> {
  return vi.fn(async () => jsonResponse(body));
}

afterEach(() => {
  vi.useRealTimers();
});

describe("askJev — request shape", () => {
  it("posts { model, state, questions } with a bearer header", async () => {
    const fetchImpl = okFetch();
    await askJev(CFG, "a suspicious run key", QUESTIONS, fetchImpl);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(CFG.baseUrl);
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${KEY}`);
    expect(JSON.parse(String(init.body))).toEqual({
      model: "typesafe/jev-1.13",
      state: "a suspicious run key",
      questions: QUESTIONS,
    });
  });

  it("accepts an object state, not only a string", async () => {
    const fetchImpl = okFetch();
    await askJev(CFG, { path: "C:/Windows/Temp/a.ps1" }, QUESTIONS, fetchImpl);
    const [, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(init.body)).state).toEqual({ path: "C:/Windows/Temp/a.ps1" });
  });

  it("rejects a state that cannot be serialized, before any request", async () => {
    const fetchImpl = okFetch();
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    await expect(askJev(CFG, circular, QUESTIONS, fetchImpl as unknown as typeof fetch)).rejects.toThrow(
      /state could not be serialized/i,
    );
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe("askJev — question validation at the boundary", () => {
  const never = () => {
    throw new Error("fetch must not run");
  };

  it("rejects a score with fewer than 2 levels and names the question id", async () => {
    const bad: Record<string, JevQuestion> = {
      severity: { type: "score", instructions: "How bad?", criteria: ["Only one"] },
    };
    await expect(askJev(CFG, "s", bad, never as unknown as typeof fetch)).rejects.toThrow(/"severity"/);
    await expect(askJev(CFG, "s", bad, never as unknown as typeof fetch)).rejects.toThrow(/2\.\.10/);
  });

  it("rejects a score with more than 10 levels", async () => {
    const bad: Record<string, JevQuestion> = {
      severity: {
        type: "score",
        instructions: "How bad?",
        criteria: Array.from({ length: 11 }, (_v, i) => `level ${i}`),
      },
    };
    await expect(askJev(CFG, "s", bad, never as unknown as typeof fetch)).rejects.toThrow(/"severity"/);
  });

  it("rejects a choice with 300 options and names the question id", async () => {
    const criteria: Record<string, string | null> = {};
    for (let i = 0; i < 300; i++) criteria[`opt${i}`] = `option ${i}`;
    const bad: Record<string, JevQuestion> = { bucket: { type: "choice", instructions: "Which?", criteria } };
    await expect(askJev(CFG, "s", bad, never as unknown as typeof fetch)).rejects.toThrow(/"bucket"/);
    await expect(askJev(CFG, "s", bad, never as unknown as typeof fetch)).rejects.toThrow(/255/);
  });

  it("rejects a choice with no options", async () => {
    const bad: Record<string, JevQuestion> = {
      bucket: { type: "choice", instructions: "Which?", criteria: {} },
    };
    await expect(askJev(CFG, "s", bad, never as unknown as typeof fetch)).rejects.toThrow(/"bucket"/);
  });

  it("rejects empty instructions", async () => {
    const bad: Record<string, JevQuestion> = { flag: { type: "noul", instructions: "   " } };
    await expect(askJev(CFG, "s", bad, never as unknown as typeof fetch)).rejects.toThrow(
      /"flag".*instructions/is,
    );
  });

  it("rejects an empty question map — a decision call with nothing to decide", async () => {
    await expect(askJev(CFG, "s", {}, never as unknown as typeof fetch)).rejects.toThrow(/at least one/i);
  });
});

describe("askJev — answer parsing", () => {
  it("parses score, choice and noul answers, keeping a fractional score", async () => {
    const res = await askJev(CFG, "s", QUESTIONS, okFetch());
    expect(res.model).toBe("typesafe/jev-1.13");
    expect(res.answers.severity).toEqual(ANSWERS.severity);
    expect(res.answers.severity.type === "score" && res.answers.severity.score).toBe(2.45);
    expect(res.answers.category.type === "choice" && res.answers.category.choice).toBe("persistence");
    expect(res.answers.needs_analyst.type === "noul" && res.answers.needs_analyst.noul).toBe(0.82);
  });

  it("reports OpenRouter usage including the dollar cost", async () => {
    const res = await askJev(CFG, "s", QUESTIONS, okFetch());
    expect(res.usage).toEqual({ inputTokens: 412, outputTokens: 18, costUSD: 0.0000312 });
  });

  it("leaves costUSD unset on the TypeSafe direct route, which prices nothing", async () => {
    const direct = { model: "jev-latest", answers: ANSWERS, usage: { input_tokens: 400, output_tokens: 12 } };
    const res = await askJev(CFG, "s", QUESTIONS, okFetch(direct));
    expect(res.usage.costUSD).toBeUndefined();
    expect(res.usage.inputTokens).toBe(400);
  });

  it("throws, naming the id, when an expected answer is missing", async () => {
    const partial = { model: "m", answers: { severity: ANSWERS.severity }, usage: {} };
    await expect(askJev(CFG, "s", QUESTIONS, okFetch(partial) as unknown as typeof fetch)).rejects.toThrow(
      /"category"/,
    );
  });

  it("throws when an answer's type does not match the question's type", async () => {
    const mismatched = {
      model: "m",
      answers: { ...ANSWERS, needs_analyst: ANSWERS.category },
      usage: {},
    };
    await expect(askJev(CFG, "s", QUESTIONS, okFetch(mismatched) as unknown as typeof fetch)).rejects.toThrow(
      /"needs_analyst".*noul/is,
    );
  });

  it("throws when a noul probability is outside 0..1", async () => {
    const outOfRange = {
      model: "m",
      answers: { ...ANSWERS, needs_analyst: { type: "noul", noul: 4 } },
      usage: {},
    };
    await expect(askJev(CFG, "s", QUESTIONS, okFetch(outOfRange) as unknown as typeof fetch)).rejects.toThrow(
      /"needs_analyst"/,
    );
  });

  it("throws when a choice lands on an option that was never offered", async () => {
    const offMenu = {
      model: "m",
      answers: {
        ...ANSWERS,
        category: { type: "choice", choice: "invented", probabilities: {}, confidence: 0.5 },
      },
      usage: {},
    };
    await expect(askJev(CFG, "s", QUESTIONS, okFetch(offMenu) as unknown as typeof fetch)).rejects.toThrow(
      /"category"/,
    );
  });

  it("throws when the body carries no answers map at all", async () => {
    await expect(
      askJev(CFG, "s", QUESTIONS, okFetch({ model: "m" }) as unknown as typeof fetch),
    ).rejects.toThrow(/answers/i);
  });

  it("throws a clear error when the body is not JSON", async () => {
    const notJson = vi.fn(async () => new Response("<html>gateway</html>", { status: 200 }));
    await expect(askJev(CFG, "s", QUESTIONS, notJson as unknown as typeof fetch)).rejects.toThrow(/JSON/i);
  });
});

describe("askJev — retry policy", () => {
  it("retries a 429 with backoff and then succeeds", async () => {
    vi.useFakeTimers();
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ error: "rate limited" }, 429))
      .mockResolvedValueOnce(jsonResponse(OPENROUTER_BODY));
    const pending = askJev(CFG, "s", QUESTIONS, fetchImpl);
    await vi.advanceTimersByTimeAsync(2_000);
    const res = await pending;
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(res.answers.needs_analyst.type === "noul" && res.answers.needs_analyst.noul).toBe(0.82);
  });

  it("does NOT retry a 422 — a malformed question is a wall, not a blip", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({ error: { message: "questions.severity.criteria is invalid" } }, 422),
    );
    await expect(askJev(CFG, "s", QUESTIONS, fetchImpl as unknown as typeof fetch)).rejects.toThrow(
      /422.*criteria/is,
    );
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("does NOT retry a 400 or a 401", async () => {
    for (const status of [400, 401]) {
      const fetchImpl = vi.fn(async () => jsonResponse({ error: "no" }, status));
      await expect(askJev(CFG, "s", QUESTIONS, fetchImpl as unknown as typeof fetch)).rejects.toThrow(
        new RegExp(String(status)),
      );
      expect(fetchImpl).toHaveBeenCalledTimes(1);
    }
  });

  it("gives up after maxRetries and surfaces the last failure", async () => {
    vi.useFakeTimers();
    const fetchImpl = vi.fn(async () => jsonResponse({ error: "overloaded" }, 529));
    const pending = askJev({ ...CFG, maxRetries: 2 }, "s", QUESTIONS, fetchImpl);
    const assertion = expect(pending).rejects.toThrow(/529/);
    await vi.advanceTimersByTimeAsync(10_000);
    await assertion;
    expect(fetchImpl).toHaveBeenCalledTimes(3); // the first try plus two retries
  });
});

describe("askJev — timeout", () => {
  it("aborts the request after timeoutMs and does not retry the timeout", async () => {
    vi.useFakeTimers();
    const fetchImpl = vi.fn(
      (_url: string, init: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        }),
    );
    const pending = askJev(CFG, "s", QUESTIONS, fetchImpl as unknown as typeof fetch);
    const assertion = expect(pending).rejects.toThrow(/timed out after 5000ms/);
    await vi.advanceTimersByTimeAsync(6_000);
    await assertion;
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});

describe("askJev — the API key never leaks", () => {
  it("keeps the key out of an HTTP error, even when the server echoes it back", async () => {
    const echo = vi.fn(async () => jsonResponse({ error: `bad key ${KEY}` }, 401));
    const err = await askJev(CFG, "s", QUESTIONS, echo as unknown as typeof fetch).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    expect(String((err as Error).message)).not.toContain(KEY);
    expect(String((err as Error).stack ?? "")).not.toContain(KEY);
    expect((err as Error).message).toMatch(/redacted/i);
  });

  it("keeps the key out of a transport error message", async () => {
    const leaky = vi.fn(async () => {
      throw new Error(`connect ECONNREFUSED while sending ${KEY}`);
    });
    const err = await askJev(
      { ...CFG, maxRetries: 0 },
      "s",
      QUESTIONS,
      leaky as unknown as typeof fetch,
    ).catch((e: unknown) => e);
    expect(String((err as Error).message)).not.toContain(KEY);
  });
});
