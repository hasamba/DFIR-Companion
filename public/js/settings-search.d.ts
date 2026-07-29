// Hand-written declarations for settings-search.js.
//
// companion/tsconfig.test.json checks the whole tests/ tree, so a test importing an untyped .js
// module fails with TS7016 and every callback derived from it becomes an implicit any — which is
// exactly why tests/analysis/commandPalette.test.ts sits on that config's exclude list. This file
// is the fix that config's own comment names, so settingsSearch.test.ts stays checked instead of
// joining the debt register.

export declare function normalize(s: unknown): string;
export declare function matchTokens(query: unknown, haystack: unknown): boolean;
export declare function landingTab(hitTabs: string[], activeTab?: string | null): string | null;
export declare function searchMessage(opts?: {
  tabs?: number;
  fields?: number;
  query?: string;
}): string;
