/**
 * Capability invocation ABI validation — the NEMO-side mirror of the Go
 * parser in internal/execution/invocation_abi.go.
 *
 * Both runtimes consume the shared conformance corpus at
 * internal/execution/testdata/invocation-abi-conformance/vectors.json
 * and must accept or reject each raw wire request identically, with the
 * same rule-level error phrases. The rules (see the Go implementation
 * for the authoritative text):
 *
 *   R1  the request is valid UTF-8
 *   R2  exactly one JSON value; nothing follows it
 *   R3  the request is a JSON object
 *   R4  no object repeats a key
 *   R5  nesting depth is at most MAX_INVOCATION_DEPTH
 *   R6  root and authority keys are from the known sets
 *   R7  explicit null is rejected for every known field
 *   R8  known fields carry their declared JSON types
 */

export type InvocationValidation = { ok: true } | { ok: false; error: string };

export const MAX_INVOCATION_DEPTH = 64;

type FieldType = "string" | "object" | "integer";

const ROOT_FIELDS = new Map<string, FieldType>([
  ["capability", "string"],
  ["arguments", "object"],
  ["authority", "object"],
  ["execution_class", "string"],
  ["idempotency_key", "string"],
  ["deadline", "string"],
]);

const AUTHORITY_FIELDS = new Map<string, FieldType>([
  ["principal", "string"],
  ["authority_ref", "string"],
  ["grant_id", "string"],
  ["authority_generation", "integer"],
  ["authority_digest", "string"],
]);

const INTEGER_LITERAL = /^-?(0|[1-9][0-9]*)$/;
const NUMBER_LITERAL = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/;
const INT64_MIN = -(2n ** 63n);
const INT64_MAX = 2n ** 63n - 1n;

/** validateInvocationRequest validates one raw wire request. */
export function validateInvocationRequest(bytes: Uint8Array): InvocationValidation {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return { ok: false, error: "request is not valid UTF-8" };
  }
  return new InvocationScanner(text).scan();
}

function typeError(path: string, expected: FieldType): string {
  switch (expected) {
    case "string":
      return `${path} must be a JSON string`;
    case "object":
      return `${path} must be a JSON object`;
    case "integer":
      return `${path} must be a JSON integer`;
  }
}

class InvocationScanner {
  private i = 0;

  constructor(private readonly text: string) {}

  scan(): InvocationValidation {
    this.skipWhitespace();
    if (this.peek() !== "{") {
      return { ok: false, error: "request must be a JSON object" };
    }
    const error = this.parseObject("request", ROOT_FIELDS, 1);
    if (error !== null) {
      return { ok: false, error };
    }
    this.skipWhitespace();
    if (this.i < this.text.length) {
      return { ok: false, error: "trailing data after the request object" };
    }
    return { ok: true };
  }

  private parseValue(
    path: string,
    expected: FieldType | null,
    depth: number,
    childFields: Map<string, FieldType> | null = null,
  ): string | null {
    const c = this.peek();
    if (c === "") {
      return "invalid JSON: unexpected end of input";
    }
    if (c === "n") {
      if (!this.consumeLiteral("null")) {
        return "invalid JSON: invalid literal";
      }
      return expected === null ? null : `null is not accepted for ${path} (omit the field instead)`;
    }
    if (c === "{") {
      if (expected !== null && expected !== "object") {
        return typeError(path, expected);
      }
      if (depth >= MAX_INVOCATION_DEPTH) {
        return `request nesting exceeds ${MAX_INVOCATION_DEPTH} levels`;
      }
      return this.parseObject(path, childFields, depth + 1);
    }
    if (c === "[") {
      if (expected !== null) {
        return typeError(path, expected);
      }
      if (depth >= MAX_INVOCATION_DEPTH) {
        return `request nesting exceeds ${MAX_INVOCATION_DEPTH} levels`;
      }
      return this.parseArray(path, depth + 1);
    }
    if (c === '"') {
      if (this.parseString() === null) {
        return "invalid JSON: invalid string";
      }
      return expected === null || expected === "string" ? null : typeError(path, expected);
    }
    if (c === "t" || c === "f") {
      const literal = c === "t" ? "true" : "false";
      if (!this.consumeLiteral(literal)) {
        return "invalid JSON: invalid literal";
      }
      return expected === null ? null : typeError(path, expected);
    }
    if (c === "-" || (c >= "0" && c <= "9")) {
      const literal = this.parseNumber();
      if (literal === null) {
        return "invalid JSON: invalid number";
      }
      if (expected === null) {
        return null;
      }
      if (expected !== "integer") {
        return typeError(path, expected);
      }
      if (!INTEGER_LITERAL.test(literal)) {
        return `${path} must be a JSON integer literal`;
      }
      const value = BigInt(literal);
      if (value < INT64_MIN || value > INT64_MAX) {
        return `${path} must fit in a signed 64-bit integer`;
      }
      return null;
    }
    return "invalid JSON: unexpected character";
  }

  private parseObject(
    path: string,
    fields: Map<string, FieldType> | null,
    depth: number,
  ): string | null {
    this.i++; // consume '{'
    const keys = new Set<string>();
    this.skipWhitespace();
    if (this.peek() === "}") {
      this.i++;
      return null;
    }
    for (;;) {
      this.skipWhitespace();
      if (this.peek() !== '"') {
        return "invalid JSON: expected an object key";
      }
      const key = this.parseString();
      if (key === null) {
        return "invalid JSON: invalid string";
      }
      if (keys.has(key)) {
        return `duplicate key ${JSON.stringify(key)} in ${path}`;
      }
      keys.add(key);
      this.skipWhitespace();
      if (this.peek() !== ":") {
        return "invalid JSON: expected ':'";
      }
      this.i++;
      this.skipWhitespace();

      if (fields !== null && !fields.has(key)) {
        return `unknown field ${JSON.stringify(key)} in ${path}`;
      }
      const expected = fields?.get(key) ?? null;
      const keyPath = `${path}.${key}`;
      const childFields = path === "request" && key === "authority" ? AUTHORITY_FIELDS : null;
      const error = this.parseValue(keyPath, expected, depth, childFields);
      if (error !== null) {
        return error;
      }

      this.skipWhitespace();
      const c = this.peek();
      if (c === ",") {
        this.i++;
        continue;
      }
      if (c === "}") {
        this.i++;
        return null;
      }
      return "invalid JSON: expected ',' or '}'";
    }
  }

  private parseArray(path: string, depth: number): string | null {
    this.i++; // consume '['
    this.skipWhitespace();
    if (this.peek() === "]") {
      this.i++;
      return null;
    }
    for (;;) {
      this.skipWhitespace();
      const error = this.parseValue(`${path}[]`, null, depth);
      if (error !== null) {
        return error;
      }
      this.skipWhitespace();
      const c = this.peek();
      if (c === ",") {
        this.i++;
        continue;
      }
      if (c === "]") {
        this.i++;
        return null;
      }
      return "invalid JSON: expected ',' or ']'";
    }
  }

  private parseString(): string | null {
    const raw = this.readStringToken();
    if (raw === null) {
      return null;
    }
    try {
      return JSON.parse(raw) as string;
    } catch {
      return null;
    }
  }

  /** readStringToken returns the raw token (with quotes) or null. */
  private readStringToken(): string | null {
    const start = this.i;
    this.i++; // opening quote
    while (this.i < this.text.length) {
      const c = this.text[this.i];
      if (c === "\\") {
        this.i += 2;
        continue;
      }
      if (c === '"') {
        this.i++;
        return this.text.slice(start, this.i);
      }
      if (c < " ") {
        return null;
      }
      this.i++;
    }
    return null;
  }

  private parseNumber(): string | null {
    const start = this.i;
    while (this.i < this.text.length && /[-+0-9.eE]/.test(this.text[this.i])) {
      this.i++;
    }
    const literal = this.text.slice(start, this.i);
    return NUMBER_LITERAL.test(literal) ? literal : null;
  }

  private consumeLiteral(literal: string): boolean {
    if (this.text.startsWith(literal, this.i)) {
      this.i += literal.length;
      return true;
    }
    return false;
  }

  private peek(): string {
    return this.i < this.text.length ? this.text[this.i] : "";
  }

  private skipWhitespace(): void {
    while (this.i < this.text.length && " \t\n\r".includes(this.text[this.i])) {
      this.i++;
    }
  }
}
