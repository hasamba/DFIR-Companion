// Gemini's `functionDeclarations[].parameters` takes its own Schema object, not full JSON Schema:
// an unknown field (`additionalProperties`, `$schema`, `oneOf`, `$ref` …) is an HTTP 400. So a tool
// schema is filtered through an ALLOWLIST of the Schema fields in the API reference
// (aistudio.google.com/api-reference, "Schema"), recursing into properties, items and anyOf.
// Argument checks never depend on the schema: every tool validates its input on the server.

const SCALAR_KEYS = [
  "format",
  "title",
  "description",
  "nullable",
  "enum",
  "maxItems",
  "minItems",
  "required",
  "minProperties",
  "maxProperties",
  "minimum",
  "maximum",
  "minLength",
  "maxLength",
  "pattern",
  "example",
  "propertyOrdering",
  "default",
] as const;

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => !!v && typeof v === "object" && !Array.isArray(v);

// A JSON Schema type list (["integer","null"]) becomes one type plus `nullable`.
function typeFields(type: unknown): Json {
  if (typeof type === "string") return { type };
  if (!Array.isArray(type)) return {};
  const real = type.filter((t) => t !== "null");
  return {
    ...(typeof real[0] === "string" ? { type: real[0] } : {}),
    ...(real.length < type.length ? { nullable: true } : {}),
  };
}

/** The schema with only Gemini Schema fields, at every level. */
export function geminiSchema(schema: unknown): Json {
  if (!isObject(schema)) return {};
  const out: Json = { ...typeFields(schema.type) };
  for (const key of SCALAR_KEYS) if (schema[key] !== undefined) out[key] = schema[key];
  if (isObject(schema.properties)) {
    out.properties = Object.fromEntries(
      Object.entries(schema.properties).map(([k, v]) => [k, geminiSchema(v)]),
    );
  }
  if (isObject(schema.items)) out.items = geminiSchema(schema.items);
  if (Array.isArray(schema.anyOf)) out.anyOf = schema.anyOf.map(geminiSchema);
  return out;
}
