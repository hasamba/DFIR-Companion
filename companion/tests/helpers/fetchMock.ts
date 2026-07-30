/**
 * A `vi.fn()` that is BOTH assignable to `FetchFn` and readable in assertions (issue #385).
 *
 * The whole enrichment/provider/integration surface takes an injectable `fetchFn?: FetchFn`, where
 * `FetchFn = typeof fetch` — an OVERLOADED signature whose first parameter is `URL | RequestInfo`.
 * A bare `vi.fn(async (url: string) => ...)` is not assignable to that, so 20+ call sites across
 * the suite silently lived in the tsconfig.test.json exclude list rather than being type-checked.
 *
 * Widening `FetchFn` in src/ to accommodate the mocks would be the wrong direction: production
 * code should keep the real `fetch` contract. So the accommodation lives here, in ONE cast, with
 * the mismatch spelled out — rather than as an `as any` repeated at every call site.
 *
 * The second thing this buys is the `.mock.calls` element type. `vi.fn(async () => resp)` declares
 * NO parameters, so `Mock<() => ...>['mock']['calls']` is `[][]` and every existing
 * `fetchFn.mock.calls[0][0]` in the suite is a TS2493 ("tuple of length 0 has no element at index
 * 0") — and the `as RequestInit` casts written to paper over it become TS2352 conversions from
 * `undefined`. Pinning the impl type to `FetchMockImpl` makes `calls[i]` a real
 * `[string, RequestInit?]`, so those assertions type-check as written and, more usefully, a test
 * that reads the wrong argument index now fails to compile.
 *
 * Usage — the `url`/`init` parameters are typed for you, so write the impl without annotations:
 *
 *   const fetchFn = fetchMock(async (url) => jsonResponse({ ok: true }));
 *   const p = new VirusTotalProvider({ apiKey: "k", fetchFn });
 *   expect(fetchFn.mock.calls[0][0]).toContain("/urls/");        // string, not never
 *   expect((fetchFn.mock.calls[0][1] as RequestInit).headers).toMatchObject({ ... });
 */
import { vi, type Mock } from "vitest";

/**
 * The shape every mock in the suite actually implements. Narrower than `fetch` on purpose: no
 * production caller passes a `Request` or `URL` object, and typing `url` as `string` is what lets
 * assertions call `new URL(url)` / `url.includes(...)` without a cast.
 */
export type FetchMockImpl = (url: string, init?: RequestInit) => Promise<Response>;

/** A `vi.fn()` that a `fetchFn?: FetchFn` option will accept, with typed `.mock.calls`. */
export type FetchMock = Mock<FetchMockImpl> & typeof fetch;

/** Wrap a fetch implementation in a `vi.fn()` that is assignable to `FetchFn`. */
export function fetchMock(impl: FetchMockImpl): FetchMock {
  // The only cast in this file, and the reason the file exists. `Mock<FetchMockImpl>` and
  // `typeof fetch` overlap on every call the code under test makes (a string URL and an optional
  // RequestInit), but TypeScript will not relate a single-signature function to an overloaded one
  // structurally, so the intersection has to be asserted.
  return vi.fn(impl) as unknown as FetchMock;
}

/** A JSON `Response`, the body most provider mocks return. */
export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}
