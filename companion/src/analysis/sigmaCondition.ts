// The Sigma `condition` grammar (#796): identifiers, `and` / `or` / `not`, parentheses, and the
// `1 of <pattern>` / `all of <pattern>` / `... of them` quantifiers. Precedence is not > and > or,
// as the Sigma specification orders it. Wildcard patterns resolve HERE, against the selection names
// the rule actually defines, so the compiler receives plain names and nothing else.
//
// Aggregations (`| count() by ...`), `near` and any other pipe stage are refused by name. A
// refusal is a sentence for the analyst, not a parser diagnostic.

import type { SigmaCondition } from "./sigmaRuleTypes.js";

export type SigmaConditionResult = { ok: true; condition: SigmaCondition } | { ok: false; message: string };

type Token = { kind: "word" | "lparen" | "rparen"; value: string };

class ConditionRefusal extends Error {}

function tokenize(text: string): Token[] {
  const pipe = text.indexOf("|");
  if (pipe >= 0) {
    const stage = text.slice(pipe + 1).trim();
    if (/^near\b/i.test(stage)) throw new ConditionRefusal("the 'near' correlation is not supported");
    throw new ConditionRefusal(`aggregations after '|' are not supported (got '| ${stage}')`);
  }
  const tokens: Token[] = [];
  const re = /\s+|(\()|(\))|([^\s()]+)/gy;
  let m: RegExpExecArray | null;
  let last = 0;
  while ((m = re.exec(text)) !== null) {
    last = re.lastIndex;
    if (m[1]) tokens.push({ kind: "lparen", value: "(" });
    else if (m[2]) tokens.push({ kind: "rparen", value: ")" });
    else if (m[3]) tokens.push({ kind: "word", value: m[3] });
    if (re.lastIndex === m.index) re.lastIndex++;
  }
  if (last < text.length) throw new ConditionRefusal(`unexpected text at '${text.slice(last).trim()}'`);
  return tokens;
}

/** Sigma's `*` / `?` selection-name wildcards, anchored, against the names the rule defines. */
function resolvePattern(pattern: string, names: readonly string[]): string[] {
  if (pattern.toLowerCase() === "them") return [...names];
  if (!/[*?]/.test(pattern)) {
    if (!names.includes(pattern))
      throw new ConditionRefusal(`selection '${pattern}' is not defined under detection`);
    return [pattern];
  }
  const re = new RegExp(
    "^" +
      pattern
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, ".*")
        .replace(/\?/g, ".") +
      "$",
  );
  const matched = names.filter((n) => re.test(n));
  if (matched.length === 0) throw new ConditionRefusal(`'${pattern}' matches no selection under detection`);
  return matched;
}

class Parser {
  private index = 0;

  constructor(
    private readonly tokens: readonly Token[],
    private readonly names: readonly string[],
  ) {}

  parse(): SigmaCondition {
    const condition = this.parseOr();
    const extra = this.tokens[this.index];
    if (extra) throw new ConditionRefusal(`unexpected '${extra.value}' after the condition`);
    return condition;
  }

  private peekWord(): string | undefined {
    const t = this.tokens[this.index];
    return t?.kind === "word" ? t.value.toLowerCase() : undefined;
  }

  private parseOr(): SigmaCondition {
    const operands = [this.parseAnd()];
    while (this.peekWord() === "or") {
      this.index++;
      operands.push(this.parseAnd());
    }
    return operands.length === 1 ? operands[0] : { kind: "or", operands };
  }

  private parseAnd(): SigmaCondition {
    const operands = [this.parseNot()];
    while (this.peekWord() === "and") {
      this.index++;
      operands.push(this.parseNot());
    }
    return operands.length === 1 ? operands[0] : { kind: "and", operands };
  }

  private parseNot(): SigmaCondition {
    if (this.peekWord() === "not") {
      this.index++;
      return { kind: "not", operand: this.parseNot() };
    }
    return this.parsePrimary();
  }

  private parsePrimary(): SigmaCondition {
    const t = this.tokens[this.index];
    if (!t) throw new ConditionRefusal("the condition ends where a selection name was expected");
    if (t.kind === "lparen") {
      this.index++;
      const inner = this.parseOr();
      if (this.tokens[this.index]?.kind !== "rparen")
        throw new ConditionRefusal("missing ')' to close a group");
      this.index++;
      return inner;
    }
    if (t.kind === "rparen") throw new ConditionRefusal("unexpected ')' with no group to close");
    if (
      this.tokens[this.index + 1]?.kind === "word" &&
      this.tokens[this.index + 1].value.toLowerCase() === "of"
    ) {
      return this.parseQuantifier(t.value);
    }
    if (["and", "or", "not", "of", "them"].includes(t.value.toLowerCase())) {
      throw new ConditionRefusal(`unexpected '${t.value}' where a selection name was expected`);
    }
    this.index++;
    return { kind: "ref", name: resolvePattern(t.value, this.names)[0] };
  }

  private parseQuantifier(count: string): SigmaCondition {
    const kind = count === "1" ? "oneOf" : count.toLowerCase() === "all" ? "allOf" : null;
    if (!kind) throw new ConditionRefusal(`only '1 of' and 'all of' are supported, not '${count} of'`);
    const pattern = this.tokens[this.index + 2];
    if (!pattern || pattern.kind !== "word")
      throw new ConditionRefusal(`'${count} of' needs a selection name or pattern after it`);
    this.index += 3;
    return { kind, names: resolvePattern(pattern.value, this.names) };
  }
}

/**
 * Parse a `condition` string against the selection names the rule defines. Pure; never throws.
 */
export function parseSigmaCondition(text: string, selectionNames: readonly string[]): SigmaConditionResult {
  try {
    const condition = new Parser(tokenize(text), selectionNames).parse();
    return { ok: true, condition };
  } catch (error) {
    if (error instanceof ConditionRefusal) return { ok: false, message: error.message };
    throw error;
  }
}
