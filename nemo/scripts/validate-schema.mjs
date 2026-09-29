#!/usr/bin/env node
/**
 * The pinned JSON Schema validator for the release verifier.
 *
 * Replaces the `ajv-cli` binary: `ajv` is an exactly-pinned dependency of
 * this package (see nemo/package-lock.json), so `npm ci --prefix nemo`
 * provides the validator without the ajv-cli transitive toolchain.
 *
 * Usage: node validate-schema.mjs <schema.json> <data.json>
 * Exit codes: 0 valid, 1 invalid (errors on stderr), 2 usage error.
 */
import { readFileSync } from "node:fs";

import Ajv from "ajv";

const [schemaPath, dataPath] = process.argv.slice(2);
if (!schemaPath || !dataPath) {
  console.error("usage: validate-schema.mjs <schema.json> <data.json>");
  process.exit(2);
}

const ajv = new Ajv({ allErrors: true, strict: false });
const validate = ajv.compile(JSON.parse(readFileSync(schemaPath, "utf8")));
if (!validate(JSON.parse(readFileSync(dataPath, "utf8")))) {
  console.error(ajv.errorsText(validate.errors, { separator: "\n" }));
  process.exit(1);
}
