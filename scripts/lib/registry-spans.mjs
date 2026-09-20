#!/usr/bin/env node
// Emits the SHA-256 of each top-level element's exact canonical bytes in
// a canonical descriptor array, as TSV rows: <sha256>\t<id>.
//
// The registry envelope carries the exact canonical bytes the Go
// producer hashed. Go marshals each descriptor independently, so a
// descriptor's canonical bytes are a contiguous span of the payload:
// hashing that span reproduces DescriptorDigest without a second
// canonicalizer participating in the trust boundary. Re-serializing the
// parsed descriptor instead would change key order and number spelling
// — exactly the bytes the digest covers.
//
// Usage: node registry-spans.mjs <payload.json>
// Exit:  0 on success; 1 if the input is not a JSON array of descriptor
//        objects carrying a non-empty string id.

import crypto from "node:crypto";
import fs from "node:fs";

const path = process.argv[2];
if (!path) {
  console.error("usage: registry-spans.mjs <payload.json>");
  process.exit(1);
}

let raw;
try {
  raw = fs.readFileSync(path, "utf8");
} catch (err) {
  console.error(`cannot read ${path}: ${err.message}`);
  process.exit(1);
}

const WHITESPACE = /\s/;

// elementEnd returns the index just past the JSON value starting at
// `start`, or -1 if the value is unterminated.
function elementEnd(source, start) {
  const first = source[start];
  if (first === "{" || first === "[") {
    let depth = 0;
    let inString = false;
    let escaped = false;
    for (let i = start; i < source.length; i++) {
      const ch = source[i];
      if (inString) {
        if (escaped) escaped = false;
        else if (ch === "\\") escaped = true;
        else if (ch === '"') inString = false;
        continue;
      }
      if (ch === '"') inString = true;
      else if (ch === "{" || ch === "[") depth++;
      else if (ch === "}" || ch === "]") {
        depth--;
        if (depth === 0) return i + 1;
      }
    }
    return -1;
  }
  if (first === '"') {
    let escaped = false;
    for (let i = start + 1; i < source.length; i++) {
      const ch = source[i];
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') return i + 1;
    }
    return -1;
  }
  let i = start;
  while (i < source.length && !WHITESPACE.test(source[i]) && source[i] !== "," && source[i] !== "]") i++;
  return i;
}

// elementSpans returns the raw byte spans of the top-level array
// elements, or null if the input is not exactly one JSON array.
function elementSpans(source) {
  let i = 0;
  while (i < source.length && WHITESPACE.test(source[i])) i++;
  if (source[i] !== "[") return null;
  i++;

  const spans = [];
  let expectValue = true;
  for (;;) {
    while (i < source.length && WHITESPACE.test(source[i])) i++;
    if (i >= source.length) return null;
    if (source[i] === "]") {
      if (expectValue && spans.length > 0) return null; // trailing comma
      i++;
      break;
    }
    if (!expectValue) {
      if (source[i] !== ",") return null;
      i++;
      expectValue = true;
      continue;
    }
    const end = elementEnd(source, i);
    if (end < 0) return null;
    spans.push(source.slice(i, end));
    i = end;
    expectValue = false;
  }

  while (i < source.length && WHITESPACE.test(source[i])) i++;
  if (i !== source.length) return null; // trailing data
  return spans;
}

const spans = elementSpans(raw);
if (spans === null) {
  console.error("payload is not exactly one JSON array");
  process.exit(1);
}

const rows = [];
for (const span of spans) {
  let descriptor;
  try {
    descriptor = JSON.parse(span);
  } catch {
    console.error("payload contains an element that is not valid JSON");
    process.exit(1);
  }
  if (descriptor === null || typeof descriptor !== "object" || Array.isArray(descriptor)) {
    console.error("payload element is not a descriptor object");
    process.exit(1);
  }
  if (typeof descriptor.id !== "string" || descriptor.id.length === 0) {
    console.error("payload element has no non-empty string id");
    process.exit(1);
  }
  rows.push(`${crypto.createHash("sha256").update(span).digest("hex")}\t${descriptor.id}`);
}

process.stdout.write(rows.length ? `${rows.join("\n")}\n` : "");
