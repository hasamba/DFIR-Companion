// ESLint gate for the companion (issue #385). Before this, the repo had no lint config at all —
// only stray `// eslint-disable-next-line` comments that nothing was reading.
//
// DESIGN: a SMALL, FULLY-ENFORCED rule set. Every rule here is at "error" and the tree is clean, so
// there is no baseline file and no suppression list to rot. That is a deliberate trade against the
// bigger option: `no-base-to-string` (119 hits) and `unbound-method` (45) both find real fragility
// and both are worth doing, but adopting them here would have meant shipping a legacy-baseline
// file, which is exactly the mechanism that let ~250 test type errors accumulate unnoticed. They
// are a tracked follow-up instead. Adding a rule to this file means fixing its violations in the
// same PR.
//
// Type-aware rules run against tsconfig.test.json, not tsconfig.json, because that is the project
// that contains the tests — linting src/ under the build config would leave the whole suite
// unlinted, repeating the #385 hole one layer up.
//
// Run it: `npm run lint` (or `npm run lint:fix` for the autofixable half).

import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    // Nothing generated, vendored or emitted is linted. `data/` is ATT&CK/D3FEND/centroid JSON,
    // `examples/` is importer sample data, `dist/` and `cases/` are outputs. None contain
    // hand-maintained TypeScript; all of them would otherwise slow the run for zero signal.
    ignores: ["dist/**", "node_modules/**", "data/**", "examples/**", "cases/**", "coverage/**"],
  },

  js.configs.recommended,

  {
    // The packaging scripts (build-sea, build-appimage, build-choco, clean-vitest-temp) are plain
    // JS, not TypeScript, so nothing tells ESLint that `process`, `console` and `Buffer` exist.
    // Without this every one of them is a no-undef.
    files: ["**/*.mjs", "**/*.cjs", "**/*.js"],
    languageOptions: { globals: globals.node },
  },

  {
    files: ["src/**/*.ts", "scripts/**/*.ts", "tests/**/*.ts"],
    extends: [tseslint.configs.base],
    languageOptions: {
      parserOptions: {
        project: "./tsconfig.test.json",
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // ---------------------------------------------------------------------------------------
      // Unhandled async work. The pair the issue asks for.
      // ---------------------------------------------------------------------------------------
      // A promise nobody awaits and nobody catches: on rejection Node prints an
      // UnhandledPromiseRejection and, since Node 15, kills the process. `void thePromise` is the
      // accepted way to say "fire and forget, deliberately" — it is a statement of intent that
      // survives review, unlike a bare call.
      "@typescript-eslint/no-floating-promises": "error",
      // checksVoidReturn is OFF because src/server.ts imports `express-async-errors`, which patches
      // the Express 4 router so an async handler's rejection reaches the terminal error middleware.
      // With it on, every `app.get("/x", async (req, res) => …)` in the codebase would be a false
      // positive. What stays on is the part express-async-errors does not cover: `if (promise)`,
      // `promise && x`, spreading a promise — conditions that are always truthy and silently wrong.
      "@typescript-eslint/no-misused-promises": ["error", { checksVoidReturn: false }],
      // `await` on a non-thenable is a no-op that reads like synchronisation — usually a forgotten
      // call parenthesis or a function that stopped being async.
      "@typescript-eslint/await-thenable": "error",
      "@typescript-eslint/prefer-promise-reject-errors": "error",
      "@typescript-eslint/only-throw-error": "error",

      // ---------------------------------------------------------------------------------------
      // Boundary validation + mutation. See the `no-restricted-syntax` block below for the two
      // project-specific selectors; these are the general-purpose half.
      // ---------------------------------------------------------------------------------------
      // Mutating a property of a parameter inside a route handler writes through to whatever the
      // caller still holds — for an Express handler that is per-request state shared with the rest
      // of the middleware chain. Scoped to routes/ (the HTTP boundary); see the src/server.ts
      // override below for why the app-options rebuild path is exempt.
      //
      // `req` and `res` are exempt because writing to them IS the Express extension mechanism:
      // `res.locals.cspNonce` (securityHeaders) and `req.rawBody` (the body-parser verify hook)
      // are the documented ways to attach per-request data, and flagging them makes the rule fight
      // the framework rather than protect anything. What stays covered is the app's OWN shared
      // objects — options, ctx, state — which nothing is supposed to write through.
      //
      // `budget` is a `{ n: number }` counter threaded through walkCaseFiles' recursion precisely
      // so every level decrements the same cap; passing it by value would remove the cap.
      "no-param-reassign": [
        "error",
        { props: true, ignorePropertyModificationsFor: ["req", "res", "budget"] },
      ],
      "@typescript-eslint/no-array-delete": "error",
      "@typescript-eslint/no-for-in-array": "error",

      // ---------------------------------------------------------------------------------------
      // Type-system honesty. These exist so the typecheck gate cannot be talked out of.
      // ---------------------------------------------------------------------------------------
      // The issue's own constraint, made mechanical: no `any` and no `@ts-ignore` as a way past a
      // type error. `ts-expect-error` is allowed WITH a description, because it fails the build the
      // day the underlying problem is fixed — `ts-ignore` never does.
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/ban-ts-comment": [
        "error",
        {
          "ts-expect-error": "allow-with-description",
          "ts-ignore": true,
          "ts-nocheck": true,
          "ts-check": false,
        },
      ],
      // A cast the compiler can already prove is redundant is either dead weight or, more often,
      // a leftover from when the underlying type was wrong — and it hides the next real mismatch.
      "@typescript-eslint/no-unnecessary-type-assertion": "error",
      "@typescript-eslint/no-unsafe-declaration-merging": "error",
      "@typescript-eslint/no-unsafe-function-type": "error",
      "@typescript-eslint/no-duplicate-type-constituents": "error",
      "@typescript-eslint/restrict-plus-operands": "error",
      "@typescript-eslint/no-implied-eval": "error",
      "@typescript-eslint/no-require-imports": "error",
      // Leading underscore is the project's existing "deliberately unused" marker (see the many
      // `_req` / `_email` parameters). caughtErrors is off: `catch {}` and `catch (e) {}` are both
      // used to mean "any failure here is non-fatal", and neither is a defect.
      // ignoreRestSiblings keeps the omit idiom legal: `({ secret, ...rest }) => rest` names the
      // field precisely so it can be DROPPED, and redactChannel/stripAiExtractedFrom both rely on
      // it. Renaming those bindings to `_secret` would break the omission.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrors: "none", ignoreRestSiblings: true },
      ],

      // ---------------------------------------------------------------------------------------
      // Baseline hygiene.
      // ---------------------------------------------------------------------------------------
      "prefer-const": "error",
      "no-var": "error",
      // "smart" keeps `x == null` (the idiomatic null-or-undefined check) and requires === elsewhere.
      eqeqeq: ["error", "smart"],
      // The server logs through serverLogger, but scripts/ are CLIs and tests print diagnostics.
      "no-console": "off",
      // Superseded by the TS rule above, which understands type-only usage.
      "no-unused-vars": "off",
      "no-undef": "off", // TypeScript resolves identifiers; this rule only produces false positives.
      // A TypeScript overload set (see serverAssets.ts's readPublicAsset) is three declarations of
      // one name, which the base rule cannot tell from an actual redeclaration.
      "no-redeclare": "off",
      // The path/filename sanitizers match `[\x00-\x1f]` on purpose — stripping control characters
      // IS the job, so flagging them means annotating every sanitizer in the codebase to say so.
      "no-control-regex": "off",
      // `-` and `/` stay escapable inside character classes. Every one of the ~40 hits is a
      // filename/path sanitizer written as `[^\w.\-]` or a base64 class written as `[A-Za-z0-9+\/]`,
      // where the backslash says "literal hyphen, not a range" and "literal slash, not a delimiter"
      // to the reader even though the engine does not need it. The rule is kept for everything else
      // (a stray `\a` in a string is still an error) — the alternative was 40 mechanical edits
      // inside path-traversal defences, which is a bad trade for a stylistic win.
      "no-useless-escape": ["error", { allowRegexCharacters: ["-", "/", "["] }],

      // ---------------------------------------------------------------------------------------
      // Project-specific selectors.
      // ---------------------------------------------------------------------------------------
      "no-restricted-syntax": [
        "error",
        {
          // FORBIDDEN BROAD TIMELINE READS (#385, enforcing #373's criterion).
          //
          // `query(caseId, { limit: Number.MAX_SAFE_INTEGER })` pulls a case's ENTIRE super-timeline
          // into memory to answer a question about a handful of rows. On a real case that is
          // hundreds of thousands of events per request. There were exactly seven of these when
          // this rule was written — in caseLifecycle, timeline, threatIntel, analysisGraph and
          // pipeline — each carrying an eslint-disable naming #373, the issue that removes them.
          //
          // The rule is here rather than in #373 so that the count can only go DOWN: #373 deletes
          // disables, and a new unbounded read cannot be added without arguing for it in review.
          selector:
            "Property[key.name='limit'] > MemberExpression[object.name='Number'][property.name='MAX_SAFE_INTEGER']",
          message:
            "Unbounded timeline read: `limit: Number.MAX_SAFE_INTEGER` loads a whole case into memory. Page the query, or push the filter into the store. See #373.",
        },
        {
          // EXPLICIT BOUNDARY VALIDATION (#385) — request bodies.
          //
          // `req.body as { name?: string }` ASSERTS a shape the wire never promised: a client that
          // posts `{"name": 42}` produces a value typed `string` that is a number at runtime, and
          // every downstream `.trim()` throws. The safe form the rest of the codebase already uses
          // is `req.body as { name?: unknown }`, which forces a narrowing step before the value is
          // read. This rule bans the unsafe form and leaves the safe one alone.
          selector:
            "TSAsExpression[expression.object.name='req'][expression.property.name='body'] TSPropertySignature > TSTypeAnnotation > :matches(TSStringKeyword, TSNumberKeyword, TSBooleanKeyword, TSArrayType, TSTypeReference)",
          message:
            "Unvalidated request boundary: assert `req.body as { field?: unknown }` and narrow, or parse it with a zod schema. A cast to a concrete type is a promise the client never made.",
        },
        {
          // Same hazard, same fix, for the query string — where EVERY value is a string or an
          // array of strings no matter what the type says.
          selector:
            "TSAsExpression[expression.object.name='req'][expression.property.name='query'] TSPropertySignature > TSTypeAnnotation > :matches(TSNumberKeyword, TSBooleanKeyword, TSTypeReference)",
          message:
            "Unvalidated request boundary: query-string values are always strings. Assert `req.query as { field?: unknown }` and narrow.",
        },
        {
          // ACCIDENTAL MUTATION AT A CRITICAL BOUNDARY (#385).
          //
          // `(await client.listClientArtifacts(id)).push(x)` mutates whatever the getter handed
          // back. When that getter serves a cache — as the Velociraptor artifact list does — the
          // write lands in the cache and every later caller sees the injected row. There is a test
          // for precisely this ("hands each caller its own array — a mutation cannot poison the
          // cache"); this rule is the same guarantee stated once, for getters nobody has written a
          // test for yet. Copy first (`[...(await x())]`) if you need to mutate.
          selector:
            "CallExpression > MemberExpression[object.type='AwaitExpression'] > Identifier.property[name=/^(push|pop|shift|unshift|splice|sort|reverse|fill|copyWithin)$/]",
          message:
            "Mutating the array an async getter just returned writes through to whatever it is backed by (often a cache). Copy it first: `[...(await getter())]`.",
        },
      ],
    },
  },

  {
    // src/server.ts's settings-reload path REBUILDS live app options in place (`options.
    // enrichmentProviders = …`) so a saved API key takes effect without a restart. That is the
    // documented design of rebuildForPrefix, not an accident, and `options` is createApp's own
    // long-lived object rather than a caller's — so the boundary this rule protects does not exist
    // here. Narrowed to the property form; reassigning a whole parameter is still an error.
    files: ["src/server.ts"],
    rules: { "no-param-reassign": ["error", { props: false }] },
  },

  {
    // Normalizer/importer code in analysis/ builds its output by filling in an accumulator object
    // it was handed — a local construction idiom, not a write through a shared boundary. The rule
    // is about routes and stores; applying it here would only produce disables.
    files: [
      "src/analysis/**/*.ts",
      "src/enrichment/**/*.ts",
      "src/integrations/**/*.ts",
      "src/reports/**/*.ts",
    ],
    rules: { "no-param-reassign": ["error", { props: false }] },
  },

  {
    // Tests build deliberately malformed inputs and reach into internals; `no-param-reassign` and
    // the request-boundary selectors have nothing to say about them. The type-honesty rules
    // (no-explicit-any, ban-ts-comment) very much DO still apply — a test that casts its way out
    // of a type error is the exact failure #385 exists to stop, so they are not relaxed here.
    files: ["tests/**/*.ts", "scripts/**/*.ts"],
    rules: { "no-param-reassign": "off" },
  },
);
