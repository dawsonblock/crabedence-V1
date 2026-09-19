/**
 * Schema validation for capability arguments and results.
 *
 * A real JSON Schema validator (Ajv, strict mode) replaces the former
 * hand-written typeof checks. Schemas are compiled once when the
 * capability catalog loads — a schema that does not compile, or that
 * uses a construct strict mode does not recognize, fails registry
 * loading instead of silently weakening validation at execution time.
 *
 * The validator is deliberately fail-closed in both directions:
 *
 *   - arguments are validated before any routing or dispatch
 *   - declared result schemas are validated on SUCCEEDED outcomes, so
 *     a supposedly trusted function cannot violate its own contract
 */
import Ajv, { type ErrorObject, type ValidateFunction } from "ajv";

/** SchemaCompilationError is thrown when a declared schema cannot be
 * compiled — the capability must not enter the active catalog. */
export class SchemaCompilationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SchemaCompilationError";
  }
}

/** Compiled validators for one capability. */
export interface CompiledSchemas {
  readonly input?: ValidateFunction;
  readonly result?: ValidateFunction;
}

export class SchemaValidator {
  private readonly ajv: Ajv;

  constructor() {
    // strict: true turns unknown keywords, malformed keyword shapes,
    // and ignored-union constructs into compile errors rather than
    // silently under-validated schemas.
    //
    // strictRequired is deliberately disabled: requiring a property
    // without declaring it under `properties` is valid JSON Schema and
    // is accepted by the authoritative Go registry, so the kernel's
    // validator must not reject a schema the registry admits.
    this.ajv = new Ajv({ strict: true, strictRequired: false, allErrors: true });
  }

  /**
   * compile compiles a capability's declared schemas. Throws
   * SchemaCompilationError when a schema is not a compilable JSON
   * Schema document.
   */
  compile(
    capabilityId: string,
    schema: unknown,
    resultSchema: unknown,
  ): CompiledSchemas {
    const compiled: { input?: ValidateFunction; result?: ValidateFunction } = {};
    if (schema !== undefined && schema !== null) {
      compiled.input = this.compileOne(capabilityId, "argument", schema);
    }
    if (resultSchema !== undefined && resultSchema !== null) {
      compiled.result = this.compileOne(capabilityId, "result", resultSchema);
    }
    return compiled;
  }

  /**
   * validate runs a compiled validator. Returns null when the value is
   * valid (or when no schema was declared), or a readable error.
   */
  validate(
    validate: ValidateFunction | undefined,
    value: unknown,
    direction: "argument" | "result",
  ): string | null {
    if (!validate) {
      return null;
    }
    if (validate(value)) {
      return null;
    }
    return `${direction} schema validation failed: ${formatErrors(validate.errors)}`;
  }

  private compileOne(
    capabilityId: string,
    kind: "argument" | "result",
    schema: unknown,
  ): ValidateFunction {
    if (typeof schema !== "object" || schema === null || Array.isArray(schema)) {
      throw new SchemaCompilationError(
        `capability ${capabilityId}: ${kind} schema must be a JSON Schema object`,
      );
    }
    try {
      return this.ajv.compile(schema as object);
    } catch (error) {
      throw new SchemaCompilationError(
        `capability ${capabilityId}: ${kind} schema does not compile: ${(error as Error).message}`,
      );
    }
  }
}

function formatErrors(errors: ErrorObject[] | null | undefined): string {
  if (!errors || errors.length === 0) {
    return "no matching schema";
  }
  return errors
    .map((error) => `${error.instancePath || "/"} ${error.message ?? "is invalid"}`)
    .join("; ");
}
