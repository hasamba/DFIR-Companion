import { canonicalHuntFieldName, resolveHuntField, suggestHuntFields } from "./huntQueryFields.js";
import type {
  HuntExpression,
  HuntParameter,
  HuntPipelineStage,
  HuntPredicate,
  HuntPredicateOperator,
  HuntQueryErrorShape,
  HuntStatistic,
  HuntStatisticFunction,
  HuntValue,
  ParsedHuntQuery,
} from "./huntQueryTypes.js";

type TokenKind =
  | "word"
  | "string"
  | "number"
  | "parameter"
  | "regex"
  | "operator"
  | "lparen"
  | "rparen"
  | "pipe"
  | "comma"
  | "eof";

interface Token {
  kind: TokenKind;
  value: string;
  offset: number;
  line: number;
  column: number;
  length: number;
  flags?: string;
}

const MAX_QUERY_LENGTH = 20_000;
const MAX_REGEX_LENGTH = 256;
const MAX_PIPELINE_STAGES = 20;
const MAX_AST_DEPTH = 64;
const STAT_FUNCTIONS: readonly HuntStatisticFunction[] = ["count", "min", "max", "sum", "avg"];

export class HuntQuerySyntaxError extends Error implements HuntQueryErrorShape {
  readonly name = "HuntQuerySyntaxError";

  constructor(
    readonly code: string,
    message: string,
    readonly line: number,
    readonly column: number,
    readonly length: number,
    readonly expected: string[] = [],
    readonly suggestions: string[] = [],
  ) {
    super(message);
  }

  toJSON(): HuntQueryErrorShape {
    return {
      code: this.code,
      message: this.message,
      line: this.line,
      column: this.column,
      length: this.length,
      ...(this.expected.length ? { expected: [...this.expected] } : {}),
      ...(this.suggestions.length ? { suggestions: [...this.suggestions] } : {}),
    };
  }
}

function location(
  text: string,
  offset: number,
): {
  line: number;
  column: number;
} {
  const prefix = text.slice(0, offset);
  const lines = prefix.split("\n");
  return { line: lines.length, column: (lines.at(-1)?.length ?? 0) + 1 };
}

function syntaxError(
  text: string,
  offset: number,
  length: number,
  code: string,
  message: string,
  expected: string[] = [],
  suggestions: string[] = [],
): HuntQuerySyntaxError {
  const at = location(text, offset);
  return new HuntQuerySyntaxError(
    code,
    message,
    at.line,
    at.column,
    Math.max(1, length),
    expected,
    suggestions,
  );
}

function decodeQuoted(text: string, start: number): { value: string; end: number } {
  const quote = text[start];
  let value = "";
  for (let index = start + 1; index < text.length; index++) {
    const char = text[index];
    if (char === quote) return { value, end: index + 1 };
    if (char === "\\") {
      index++;
      if (index >= text.length) break;
      const escaped = text[index];
      value += escaped === "n" ? "\n" : escaped === "r" ? "\r" : escaped === "t" ? "\t" : escaped;
    } else {
      value += char;
    }
  }
  throw syntaxError(text, start, 1, "unterminated_string", "Quoted value is not terminated", [quote]);
}

function decodeRegex(text: string, start: number): { value: string; flags: string; end: number } {
  let value = "";
  let escaped = false;
  let index = start + 1;
  for (; index < text.length; index++) {
    const char = text[index];
    if (!escaped && char === "/") break;
    value += char;
    escaped = !escaped && char === "\\";
    if (char !== "\\") escaped = false;
  }
  if (index >= text.length) {
    throw syntaxError(text, start, 1, "unterminated_regex", "Regular expression is not terminated", ["/"]);
  }
  index++;
  const flagsStart = index;
  while (/[A-Za-z]/.test(text[index] ?? "")) index++;
  return {
    value,
    flags: text.slice(flagsStart, index),
    end: index,
  };
}

function tokenize(text: string): Token[] {
  const tokens: Token[] = [];
  let index = 0;
  const push = (kind: TokenKind, value: string, start: number, end: number, flags?: string): void => {
    const at = location(text, start);
    tokens.push({
      kind,
      value,
      offset: start,
      line: at.line,
      column: at.column,
      length: Math.max(1, end - start),
      ...(flags ? { flags } : {}),
    });
  };

  while (index < text.length) {
    if (/\s/.test(text[index])) {
      index++;
      continue;
    }
    const start = index;
    const char = text[index];
    if (char === "'" || char === '"') {
      const quoted = decodeQuoted(text, start);
      push("string", quoted.value, start, quoted.end);
      index = quoted.end;
      continue;
    }
    if (char === "/") {
      const regex = decodeRegex(text, start);
      push("regex", regex.value, start, regex.end, regex.flags);
      index = regex.end;
      continue;
    }
    if (char === "$") {
      index++;
      while (/[A-Za-z0-9_]/.test(text[index] ?? "")) index++;
      const name = text.slice(start + 1, index);
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
        throw syntaxError(
          text,
          start,
          index - start,
          "invalid_parameter",
          "Parameter names use $name syntax",
          ["$name"],
        );
      }
      push("parameter", name, start, index);
      continue;
    }
    const punctuation: Partial<Record<string, TokenKind>> = {
      "(": "lparen",
      ")": "rparen",
      "|": "pipe",
      ",": "comma",
    };
    const punctuationKind = punctuation[char];
    if (punctuationKind) {
      push(punctuationKind, char, start, start + 1);
      index++;
      continue;
    }
    const paired = text.slice(index, index + 2);
    if ([">=", "<=", "!=", "=~", "!~"].includes(paired)) {
      push("operator", paired, start, start + 2);
      index += 2;
      continue;
    }
    if (["=", ">", "<"].includes(char)) {
      push("operator", char, start, start + 1);
      index++;
      continue;
    }
    while (
      index < text.length &&
      !/\s/.test(text[index]) &&
      !["(", ")", "|", ",", "=", "!", ">", "<", "/", "$", '"', "'"].includes(text[index])
    ) {
      index++;
    }
    if (index === start) {
      throw syntaxError(
        text,
        start,
        1,
        "unexpected_character",
        `Unexpected character ${JSON.stringify(char)}`,
      );
    }
    const value = text.slice(start, index);
    push(/^-?(?:\d+\.?\d*|\.\d+)$/.test(value) ? "number" : "word", value, start, index);
  }
  const at = location(text, text.length);
  tokens.push({
    kind: "eof",
    value: "",
    offset: text.length,
    line: at.line,
    column: at.column,
    length: 1,
  });
  return tokens;
}

function isParameter(value: HuntValue): value is HuntParameter {
  return value != null && typeof value === "object" && value.kind === "parameter";
}

export function validateHuntRegex(
  pattern: string,
  flags = "",
  token?: Pick<Token, "line" | "column" | "length">,
): void {
  const at = token ?? { line: 1, column: 1, length: pattern.length || 1 };
  const reject = (message: string): never => {
    throw new HuntQuerySyntaxError("unsafe_regex", message, at.line, at.column, at.length);
  };
  if (pattern.length > MAX_REGEX_LENGTH) {
    reject(`Regular expressions are limited to ${MAX_REGEX_LENGTH} characters`);
  }
  if (!/^[imsu]*$/.test(flags) || new Set(flags).size !== flags.length) {
    reject("Only unique i, m, s and u regular-expression flags are allowed");
  }
  if (/\(\?/.test(pattern)) {
    reject("Lookarounds, inline flags and special groups are not allowed");
  }
  if (/\\[1-9]/.test(pattern)) {
    reject("Regular-expression backreferences are not allowed");
  }
  if (/\([^)]*(?:\+|\*|\{\d+(?:,\d*)?\})[^)]*\)(?:\+|\*|\{)/.test(pattern)) {
    reject("Nested quantified groups are not allowed");
  }
  if (/(\.\*){2,}|(\.\+){2,}/.test(pattern)) {
    reject("Repeated wildcard quantifiers are not allowed");
  }
  try {
    new RegExp(pattern, flags);
  } catch (error) {
    reject(`Invalid regular expression: ${(error as Error).message}`);
  }
}

class Parser {
  private index = 0;
  private depth = 0;
  private readonly parameters = new Set<string>();

  constructor(
    private readonly text: string,
    private readonly tokens: readonly Token[],
  ) {}

  parse(): ParsedHuntQuery {
    const filter = this.parseOr();
    const pipeline: HuntPipelineStage[] = [];
    while (this.match("pipe")) {
      if (pipeline.length >= MAX_PIPELINE_STAGES) {
        this.fail(
          this.peek(),
          "pipeline_too_long",
          `A query may contain at most ${MAX_PIPELINE_STAGES} pipeline stages`,
        );
      }
      pipeline.push(this.parseStage());
    }
    this.expect("eof");
    return {
      text: this.text,
      filter,
      pipeline,
      parameters: [...this.parameters].sort(),
    };
  }

  private peek(offset = 0): Token {
    return this.tokens[Math.min(this.index + offset, this.tokens.length - 1)];
  }

  private take(): Token {
    const token = this.peek();
    this.index++;
    return token;
  }

  private match(kind: TokenKind, value?: string): boolean {
    const token = this.peek();
    if (token.kind !== kind || (value !== undefined && token.value.toLowerCase() !== value.toLowerCase())) {
      return false;
    }
    this.index++;
    return true;
  }

  private expect(kind: TokenKind, value?: string): Token {
    const token = this.peek();
    if (token.kind !== kind || (value !== undefined && token.value.toLowerCase() !== value.toLowerCase())) {
      const expected = value ?? kind;
      this.fail(token, "expected_token", `Expected ${expected}, found ${token.value || "end of query"}`, [
        expected,
      ]);
    }
    return this.take();
  }

  private fail(
    token: Token,
    code: string,
    message: string,
    expected: string[] = [],
    suggestions: string[] = [],
  ): never {
    throw new HuntQuerySyntaxError(
      code,
      message,
      token.line,
      token.column,
      token.length,
      expected,
      suggestions,
    );
  }

  private enter(): void {
    this.depth++;
    if (this.depth > MAX_AST_DEPTH) {
      this.fail(
        this.peek(),
        "expression_too_deep",
        `Expressions may be nested at most ${MAX_AST_DEPTH} levels`,
      );
    }
  }

  private leave<T>(value: T): T {
    this.depth--;
    return value;
  }

  private parseOr(): HuntExpression {
    this.enter();
    let expression = this.parseAnd();
    while (this.match("word", "or")) {
      expression = {
        kind: "boolean",
        operator: "or",
        left: expression,
        right: this.parseAnd(),
      };
    }
    return this.leave(expression);
  }

  private parseAnd(): HuntExpression {
    let expression = this.parseNot();
    while (this.match("word", "and")) {
      expression = {
        kind: "boolean",
        operator: "and",
        left: expression,
        right: this.parseNot(),
      };
    }
    return expression;
  }

  private parseNot(): HuntExpression {
    if (this.match("word", "not")) {
      return { kind: "not", operand: this.parseNot() };
    }
    return this.parsePrimary();
  }

  private parsePrimary(): HuntExpression {
    if (this.match("lparen")) {
      const expression = this.parseOr();
      this.expect("rparen");
      return expression;
    }
    return this.parsePredicate();
  }

  private parseField(): {
    name: string;
    token: Token;
  } {
    const token = this.expect("word");
    const name = canonicalHuntFieldName(token.value);
    if (!name) {
      this.fail(token, "unknown_field", `Unknown field ${token.value}`, [], suggestHuntFields(token.value));
    }
    return { name, token };
  }

  private parseValue(): HuntValue {
    const token = this.take();
    if (token.kind === "parameter") {
      this.parameters.add(token.value);
      return { kind: "parameter", name: token.value };
    }
    if (token.kind === "number") return Number(token.value);
    if (token.kind === "string") return token.value;
    if (token.kind === "word") {
      if (token.value.toLowerCase() === "true") return true;
      if (token.value.toLowerCase() === "false") return false;
      if (token.value.toLowerCase() === "null") return null;
      return token.value;
    }
    this.fail(token, "expected_value", `Expected a value, found ${token.value || "end of query"}`, [
      "string",
      "number",
      "$parameter",
    ]);
  }

  private parsePredicate(): HuntPredicate {
    const field = this.parseField();
    const fieldDefinition = resolveHuntField(field.name);
    const next = this.peek();
    let operator: HuntPredicateOperator;
    if (next.kind === "operator") {
      const raw = this.take().value;
      operator = raw === "=~" ? "matches" : (raw as HuntPredicateOperator);
      if (raw === "!~") {
        this.fail(next, "invalid_operator", "Use NOT field matches /pattern/ instead of !~", ["NOT"]);
      }
    } else if (
      next.kind === "word" &&
      ["contains", "matches", "exists", "between", "during"].includes(next.value.toLowerCase())
    ) {
      operator = this.take().value.toLowerCase() as HuntPredicateOperator;
    } else {
      this.fail(next, "expected_operator", `Expected an operator after ${field.name}`, [
        "=",
        "!=",
        "contains",
        "matches",
        "exists",
        "between",
        "during",
      ]);
    }

    if (operator === "during" && fieldDefinition?.type !== "timestamp") {
      this.fail(next, "invalid_operator", "during is only valid for timestamp fields");
    }
    if (operator === "exists") {
      return { kind: "predicate", field: field.name, operator };
    }
    if (operator === "matches") {
      const regex = this.take();
      if (regex.kind !== "regex" && regex.kind !== "string") {
        this.fail(regex, "expected_regex", "matches expects /pattern/flags or a quoted pattern", [
          "/pattern/i",
        ]);
      }
      validateHuntRegex(regex.value, regex.flags ?? "", regex);
      return {
        kind: "predicate",
        field: field.name,
        operator,
        value: regex.value,
        ...(regex.flags ? { regexFlags: regex.flags } : {}),
      };
    }
    const value = this.parseValue();
    if (operator === "between") {
      this.expect("word", "and");
      const upper = this.parseValue();
      return {
        kind: "predicate",
        field: field.name,
        operator,
        value,
        upper,
      };
    }
    return { kind: "predicate", field: field.name, operator, value };
  }

  private parseStage(): HuntPipelineStage {
    const stage = this.expect("word");
    switch (stage.value.toLowerCase()) {
      case "group":
        this.expect("word", "by");
        return { kind: "group", field: this.parseField().name };
      case "count":
        return { kind: "count" };
      case "stats":
        return this.parseStats();
      case "rare": {
        const field = this.parseField().name;
        const limit = this.match("word", "limit") ? this.parsePositiveInteger("rare limit", 100) : 10;
        return { kind: "rare", field, limit };
      }
      case "sort": {
        const field = this.expect("word").value;
        const direction =
          this.peek().kind === "word" && ["asc", "desc"].includes(this.peek().value.toLowerCase())
            ? (this.take().value.toLowerCase() as "asc" | "desc")
            : "asc";
        return { kind: "sort", field, direction };
      }
      case "limit":
        return {
          kind: "limit",
          limit: this.parsePositiveInteger("limit", 10_000),
        };
      default:
        this.fail(stage, "unknown_stage", `Unknown pipeline stage ${stage.value}`, [
          "group",
          "count",
          "stats",
          "rare",
          "sort",
          "limit",
        ]);
    }
  }

  private parsePositiveInteger(label: string, max: number): number {
    const token = this.expect("number");
    const value = Number(token.value);
    if (!Number.isInteger(value) || value < 1 || value > max) {
      this.fail(token, "invalid_limit", `${label} must be an integer from 1 to ${max}`);
    }
    return value;
  }

  private parseStats(): HuntPipelineStage {
    const statistics: HuntStatistic[] = [];
    do {
      const fnToken = this.expect("word");
      const fn = fnToken.value.toLowerCase() as HuntStatisticFunction;
      if (!STAT_FUNCTIONS.includes(fn)) {
        this.fail(fnToken, "unknown_statistic", `Unknown statistic ${fnToken.value}`, [...STAT_FUNCTIONS]);
      }
      this.expect("lparen");
      const field = this.peek().kind === "rparen" ? undefined : this.parseField().name;
      this.expect("rparen");
      if (fn !== "count" && !field) {
        this.fail(fnToken, "missing_statistic_field", `${fn} requires a field`);
      }
      statistics.push({
        fn,
        ...(field ? { field } : {}),
        alias: field ? `${fn}_${field}` : "count",
      });
    } while (this.match("comma"));
    const by = this.match("word", "by") ? this.parseField().name : undefined;
    return {
      kind: "stats",
      statistics,
      ...(by ? { by } : {}),
    };
  }
}

export function parseHuntQuery(text: string): ParsedHuntQuery {
  if (typeof text !== "string") {
    throw new HuntQuerySyntaxError("invalid_query", "Query text must be a string", 1, 1, 1);
  }
  if (text.length > MAX_QUERY_LENGTH) {
    throw new HuntQuerySyntaxError(
      "query_too_long",
      `Queries are limited to ${MAX_QUERY_LENGTH} characters`,
      1,
      1,
      text.length,
    );
  }
  if (!text.trim()) {
    throw new HuntQuerySyntaxError("empty_query", "Enter at least one filter expression", 1, 1, 1);
  }
  try {
    return new Parser(text, tokenize(text)).parse();
  } catch (error) {
    if (error instanceof HuntQuerySyntaxError) throw error;
    throw syntaxError(text, 0, 1, "invalid_query", `Query could not be parsed: ${(error as Error).message}`);
  }
}

function renderValue(value: HuntValue | undefined): string {
  if (value === undefined) return "";
  if (isParameter(value)) return `$${value.name}`;
  return JSON.stringify(value);
}

function explainExpression(expression: HuntExpression): string {
  if (expression.kind === "boolean") {
    return `(${explainExpression(expression.left)} ${expression.operator.toUpperCase()} ${explainExpression(expression.right)})`;
  }
  if (expression.kind === "not") {
    return `NOT ${explainExpression(expression.operand)}`;
  }
  if (expression.operator === "exists") {
    return `requires ${expression.field} to exist`;
  }
  if (expression.operator === "between") {
    return `${expression.field} is between ${renderValue(expression.value)} and ${renderValue(expression.upper)}`;
  }
  return `${expression.field} ${expression.operator} ${renderValue(expression.value)}`;
}

export function explainHuntQuery(parsed: ParsedHuntQuery): string {
  const stages = parsed.pipeline.length
    ? ` Then ${parsed.pipeline.map((stage) => stage.kind).join(", ")}.`
    : "";
  const parameters = parsed.parameters.length
    ? ` Required ${parsed.parameters.map((name) => `parameter $${name}`).join(", ")}.`
    : "";
  return `Filter: ${explainExpression(parsed.filter)}.${stages}${parameters}`;
}
