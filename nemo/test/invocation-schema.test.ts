import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { validateInvocationRequest } from "../contracts/invocation-abi";

/**
 * The published schema and this validator must not drift.
 *
 * `schemas/capability-invocation-v1.json` is the one canonical description of
 * the wire contract. The Go parser (`internal/execution/invocation_abi.go`) and
 * the Rust scanner (`runtimes/nemo-relay/bridges/nemo-crabedence/src/abi.rs`)
 * are bound to the same file by their own tests.
 *
 * The binding is behavioral rather than structural on purpose: this test asks
 * the validator, not a private constant, so a refactor cannot silently
 * disconnect the schema from what actually runs.
 */

interface SchemaField {
  readonly type?: string;
  readonly additionalProperties?: boolean;
  readonly properties?: Record<string, SchemaField>;
}

interface InvocationSchema {
  readonly type?: string;
  readonly additionalProperties?: boolean;
  readonly properties?: Record<string, SchemaField>;
  readonly "x-crabedence-server-resolved"?: string[];
}

const schema: InvocationSchema = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "../../schemas/capability-invocation-v1.json",
    ),
    "utf-8",
  ),
) as InvocationSchema;

/** A structurally valid value for one schema-declared field type. */
function valueFor(field: SchemaField): unknown {
  switch (field.type) {
    case "object":
      return {};
    case "integer":
      return 1;
    default:
      return "x";
  }
}

function accepts(wire: string): boolean {
  return validateInvocationRequest(new TextEncoder().encode(wire)).ok;
}

function refusal(wire: string): string {
  const result = validateInvocationRequest(new TextEncoder().encode(wire));
  return result.ok ? "" : result.error;
}

describe("capability invocation schema", () => {
  it("describes a closed object", () => {
    expect(schema.type).toBe("object");
    expect(schema.additionalProperties).toBe(false);
    expect(schema.properties).toBeTruthy();
  });

  it("accepts every field the schema describes", () => {
    for (const [name, field] of Object.entries(schema.properties ?? {})) {
      const wire = JSON.stringify({
        capability: "system.echo",
        [name]: valueFor(field),
      });
      expect(accepts(wire), `schema field ${name} must be accepted`).toBe(true);
    }
  });

  it("accepts every authority field the schema describes", () => {
    const authority = schema.properties?.authority;
    expect(authority?.type).toBe("object");
    expect(authority?.additionalProperties).toBe(false);
    for (const [name, field] of Object.entries(authority?.properties ?? {})) {
      const wire = JSON.stringify({
        capability: "system.echo",
        authority: { [name]: valueFor(field) },
      });
      expect(accepts(wire), `authority.${name} must be accepted`).toBe(true);
    }
  });

  it("refuses every server-resolved field the schema names", () => {
    const serverResolved = schema["x-crabedence-server-resolved"] ?? [];
    expect(serverResolved.length).toBeGreaterThan(0);
    for (const name of serverResolved) {
      expect(schema.properties?.[name], `${name} must not be accepted`).toBeUndefined();
      const error = refusal(
        JSON.stringify({ capability: "system.echo", [name]: "x" }),
      );
      expect(error, `${name} must be refused as an unknown field`).toContain(
        "unknown field",
      );
    }
  });

  it("refuses an unknown field the schema does not name", () => {
    const error = refusal(
      JSON.stringify({ capability: "system.echo", not_a_field: "x" }),
    );
    expect(error).toContain("unknown field");
  });
});
