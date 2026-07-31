# Contributing

## The gates

Seven checks run in CI on every pull request. All seven run locally, and all seven are fast enough to
run before you push. Everything below is from `companion/` unless it says otherwise.

```bash
npm run build          # tsc: compiles src/ to dist/. This is the production build.
npm run typecheck      # tsc: type-checks src/ + tests/ + scripts/, emitting nothing.
npm run lint           # eslint: typed rules over the same three trees.
npm run format:check   # prettier, on the files THIS BRANCH changed.
npm run check:size     # no source file grew past its recorded size.
npm run check:imports  # no new runtime import cycle.
npm run check:boundaries  # no import crosses a module boundary the wrong way.
npm test               # vitest: 486 files, ~6,200 tests.
```

Run the whole set in one go:

```bash
cd companion && npm run build && npm run typecheck && npm run lint && npm run format:check && npm run check:size && npm run check:imports && npm run check:boundaries && npm test
```

CI splits these across two jobs on purpose. **Companion build + test** failing means the code is
wrong; **Companion lint + format + structure** failing means it is untidy. A single combined check
would make both look equally alarming, which is how people learn to skim past red.

---

## `npm run build` — the production type-check

`tsconfig.json` is the *emit* config: `include: ["src"]`, `outDir: dist`. It is what ships. If this
fails, the server does not compile.

## `npm run typecheck` — the test type-check

`tsconfig.test.json` extends the build config with `noEmit` and adds `tests/` and `scripts/`. It has
**no exclude list**: every test file in the repo is type-checked.

That matters more than it sounds. `AnonPolicy.categories` is a `Record<AnonCategory, boolean>`, so
adding a PII category makes every object literal that omits it a compile error — the tripwire that
stops a new detector from being silently OFF in the tests that claim to cover it. For years the
tests were unchecked and the tripwire never fired: `CARD`, `PHONE` and `NATID` were missing from
four `categories` literals, disabling those three detectors across the entire redaction suite.

### When it fails

The compiler tells you the file, line and expected type. Fix the code, not the checker:

| Do | Don't |
|---|---|
| Add the missing field to the literal | Cast the literal with `as SomeType` |
| Add a factory helper if the same literal recurs (see `tests/analysis/intelVerdictGate.test.ts`'s `enr()`) | Widen the production type so the test compiles |
| `as unknown as T` **inside one shared helper**, with a comment (see `tests/helpers/fetchMock.ts`) | Sprinkle `as unknown as T` at call sites |
| Fix the production type when the test is right | `@ts-ignore` |

Two shared helpers exist so you rarely need any of this:

- **`tests/helpers/fetchMock.ts`** — a `vi.fn()` that is assignable to `FetchFn` *and* has typed
  `.mock.calls`. Use it for anything taking an injectable `fetchFn`. A bare `vi.fn(async () => resp)`
  declares no parameters, so `fetchFn.mock.calls[0][0]` is a tuple-index error.
- **`tests/helpers/poll.ts`** — deadline-based polling. Use `pollFor` instead of a fixed-iteration
  retry loop.

There is no per-file escape hatch and adding one back is a change to `tsconfig.test.json` that a
reviewer will see. If a file genuinely cannot be checked, say why in the PR.

## `npm run lint` — ESLint

`eslint.config.mjs` is a deliberately small, fully-enforced rule set: everything is `error` and the
tree is clean, so there is no baseline file to rot. Adding a rule means fixing its violations in the
same PR.

`npm run lint:fix` handles the autofixable half. **Re-run `npm run typecheck` after `lint:fix`** —
`no-unnecessary-type-assertion`'s autofix can remove an assertion that was supplying a contextual
type, which the compiler catches but the linter does not.

### The rules that will bite you, and what to do

**`no-floating-promises`** — a promise nobody awaits and nobody catches. On rejection Node kills the
process. Either `await` it, or prefix `void` to say fire-and-forget deliberately:

```ts
void logActivity(store, onActivity, caseId, { category: "ai", action: "synthesis", detail });
```

**`no-restricted-syntax` / unbounded timeline read** — `query(caseId, { limit: Number.MAX_SAFE_INTEGER })`
loads a whole case's super-timeline into memory to answer a question about a few rows. Page the
query, batch it with `eventBatches()`, or push the filter into the store.
[#373](https://github.com/hasamba/DFIR-Companion/issues/373) removed the seven that existed when
this rule was written, so it ships with no violations and nothing suppressed — it is here to stop
the eighth.

**`no-restricted-syntax` / unvalidated request boundary** — `req.body as { name?: string }` asserts a
shape the wire never promised. A client posting `{"name": 42}` gives you a value typed `string` that
is a number at runtime. Assert `unknown` and narrow:

```ts
const { name } = req.body as { name?: unknown };
if (name !== undefined && typeof name !== "string") return res.status(400).json({ error: "…" });
```

**`no-restricted-syntax` / mutating an async getter's result** — `(await store.list()).push(x)`
writes through to whatever backs that getter, often a cache. Copy first: `[...(await store.list())]`.

**`no-param-reassign`** — do not write through a parameter into the caller's object. `req` and `res`
are exempt (`res.locals` and `req.rawBody` are Express's own extension points), as is the recursive
`budget` counter in `routes/system.ts`.

**`no-explicit-any` / `ban-ts-comment`** — no `any`, no `@ts-ignore`. `@ts-expect-error` is allowed
**with a description**, because it fails the build the day the underlying problem is fixed.

## `npm run format:check` — Prettier, where it cannot make things worse

Prettier disagrees with 877 of the companion's 946 TypeScript files — about 60,000 lines of pure
reflow at every print width. Reformatting all of it in one commit would rewrite the hand-wrapped
layout this codebase is written in and rot every open branch. So the gate looks only at files your
branch changed (merge base vs. `master`, plus your working tree), and asks one question per file:

| Situation | Gate |
|---|---|
| The file is **new** | Must be formatted. New code is Prettier-clean from birth. |
| It was **already formatted** at the merge base | Must still be formatted. You may not un-format clean code. |
| It was **already unformatted** | Skipped. Your change is not the reason it is unformatted. |

The third row is what keeps the gate usable: requiring a whole-file reformat because someone deleted
an unused import turns a two-line fix into a four-hundred-line diff, which is how a format gate ends
up switched off. The invariant is **the set of Prettier-clean files never shrinks** — no baseline
file, nothing to rot, and the PR that introduced the gate passed under the same rule as every one
after it.

Converting a legacy file is a deliberate act. Run `npm run format` on it, ideally in its own commit;
from then on the gate keeps it converted.

```bash
npm run format        # format the files this branch changed (ignores the was-it-clean test)
npm run format:all    # format the entire tree — do NOT do this in a feature PR
```

Config lives in `companion/.prettierrc.json` (110-column, 2-space, double quotes, trailing commas)
and `companion/.prettierignore` (generated data, importer fixtures, the lockfile, the ratchet
ledgers, `encoded_rules.yml`).

Scope is `companion/` only — `extension/` is a separate package with its own CI job, and `public/`
is served static assets. Markdown is deliberately **not** formatted: the README, USER_MANUAL and
CHANGELOG are hand-laid-out prose with alignment Prettier would destroy.

## `npm run check:size` — the file-size ratchet

A 6,000-line module is a review problem, not a style problem: nobody reads the whole of
`analysis/pipeline.ts` before changing twenty lines of it, so nobody sees the interaction four
thousand lines away.

- A file **not** in `scripts/file-size-ledger.json` may not exceed **800 lines**. (Over 96% of
  source files are already under it — it is where this codebase already sits, not an aspiration.)
- A file **in** the ledger is frozen at its recorded length. Shrink it freely; you cannot grow it.

When it fails, put the new code in its own module. If you shrank a ledgered file, lock the smaller
number in:

```bash
npm run check:size -- --update   # shrink-only; refuses to raise a recorded number
npm run check:size -- --init     # re-baseline; prints every raise, justify them in the PR
```

`--init` is for two moments only: the first recording, and re-baselining after merging a long-lived
branch whose landed work legitimately grew a ledgered file. Reaching for it during ordinary work
means the new code belongs in its own module instead.

## `npm run check:imports` — the circular-import ratchet

A runtime import cycle means one module in the loop sees a half-initialised copy of the other. There
is exactly **one** today (`analysis/adversaryEmulation.ts ↔ analysis/adversaryHints.ts`), recorded in
`scripts/import-cycles.json`.

Type-only imports are ignored — `import type` is erased before the module runs and cannot form a
runtime cycle. That is why the 30-odd `routes/*.ts ↔ server.ts` back-references a naive tool reports
are not listed here.

When it fails, break the cycle: move the shared type or helper into its own module, or make the
back-reference `import type`. Only if the cycle is genuinely intended:

```bash
npm run check:imports -- --update   # and say why in the PR
```

---

## `npm run check:boundaries` — the module-boundary ratchet

Every file in `src/` belongs to a domain, every domain sits in a layer, and **an import may go down a
layer or sideways within one — never up.** [ARCHITECTURE.md](ARCHITECTURE.md) is the map;
`scripts/module-map.json` is what CI actually reads, and a test asserts the two agree.

Unlike `check:imports`, **type-only imports count here.** An erased import cannot form a runtime
cycle, but it still means one domain knows another's shape, which is the coupling the map exists to
control.

There are **48** recorded violations in `scripts/boundary-violations.json`, listed as
`source-file -> target-file` rather than as domain pairs — otherwise one grandfathered violation
becomes a licence to add more imports along the same edge.

When it fails on a **new violation**, the usual fixes are: move the shared helper down to a domain
both callers already depend on, invert the call so the higher layer drives, or — if the module is
simply filed in the wrong domain — correct its entry in `module-map.json`.

When it fails because a **file has no domain**, classify it. That is a hard error, never a ledger
entry: a new `src/analysis/*.ts` file needs a `flatAnalysisFiles` entry, and an unclassified file is
an unanswered design question rather than a known debt.

```bash
npm run check:boundaries -- --update   # shrink-only; refuses to add an entry
npm run check:boundaries -- --init     # re-baseline; additions are printed, justify them
```

---

## Why the gates exist

Both ratchets are prerequisites for [#384](https://github.com/hasamba/DFIR-Companion/issues/384)
(decomposing `pipeline.ts`), which needs a ceiling to enforce and a cycle count to hold flat while
it moves code around. The lint and typecheck gates come from
[#385](https://github.com/hasamba/DFIR-Companion/issues/385).

The through-line is the same in every case: **make the failure mode visible at the PR that causes
it.** Every one of these gates exists because something got in that nobody could see — an
untype-checked test that disabled three PII detectors, a `severity: "high"` that no longer matched
the `Severity` union, an unbounded query that reads a whole case to answer a small question. None of
them were caught by review, and all of them are trivially caught by a machine.

## Known follow-ups

- `@typescript-eslint/no-base-to-string` (119 sites) and `unbound-method` (45) both find real
  fragility. They are not enabled because adopting them would have meant shipping a legacy-baseline
  file — the exact mechanism that let ~250 test type errors accumulate unnoticed in the first place.
- The 14 ledgered oversized files shrink under #384.
