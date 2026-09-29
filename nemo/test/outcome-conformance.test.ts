/**
 * Outcome conformance against the shared corpus.
 *
 * `internal/execution/testdata/outcome-conformance/vectors.json` is owned by
 * the Go execution kernel. The Go test binds it to `classifyPostDispatch` and
 * the Rust bridge binds to it in `tests/outcome_conformance.rs`; this test
 * binds the reference adapter to the same expectations.
 *
 * The vector that matters most is `failed-not-definitive`: a `FAILED` response
 * without `definitive_failure: true` is ambiguous, because the kernel cannot
 * prove no effect occurred. Reporting `FAILED` would claim more certainty than
 * the kernel does, and a caller treating it as definitive may retry an effect
 * that already happened.
 */
import { readFileSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
  CrabedenceClient,
  CrabedenceExecutionAdapter,
} from "../adapters/crabedence/index";

interface OutcomeVector {
  readonly name: string;
  readonly response: unknown;
  readonly shape: "accept" | "reject";
  readonly error_contains?: string;
  readonly nemo_status?: string;
}

const corpus: { vectors: OutcomeVector[] } = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "../../internal/execution/testdata/outcome-conformance/vectors.json",
    ),
    "utf-8",
  ),
) as { vectors: OutcomeVector[] };

let counter = 0;
const openServers: Server[] = [];
const openSockets: string[] = [];

afterEach(async () => {
  await Promise.all(
    openServers.splice(0).map(
      (server) => new Promise<void>((resolve) => server.close(() => resolve())),
    ),
  );
  for (const socketPath of openSockets.splice(0)) {
    try {
      rmSync(socketPath, { force: true });
    } catch {
      // the socket is already gone
    }
  }
});

function frameFor(value: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(value), "utf-8");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.byteLength, 0);
  return Buffer.concat([header, payload]);
}

/** Serves one raw frame on a fresh socket — the exact bytes under test. */
async function serveOnce(frame: Buffer): Promise<string> {
  counter += 1;
  const socketPath = join(tmpdir(), `nemo-outcome-${process.pid}-${counter}.sock`);
  try {
    rmSync(socketPath, { force: true });
  } catch {
    // nothing to remove
  }
  const server = createServer((socket) => {
    socket.once("data", () => {
      socket.write(frame);
      socket.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(socketPath, () => resolve()));
  openServers.push(server);
  openSockets.push(socketPath);
  return socketPath;
}

describe("outcome conformance", () => {
  it("covers both outcomes", () => {
    expect(corpus.vectors.length).toBeGreaterThan(0);
    expect(corpus.vectors.some((vector) => vector.shape === "accept")).toBe(true);
    expect(corpus.vectors.some((vector) => vector.shape === "reject")).toBe(true);
  });

  for (const vector of corpus.vectors) {
    it(`classifies ${vector.name}`, async () => {
      const socketPath = await serveOnce(frameFor(vector.response));
      const adapter = new CrabedenceExecutionAdapter(
        new CrabedenceClient(socketPath, 5000),
      );

      if (vector.shape === "reject") {
        // A non-consequential class makes the adapter rethrow rather than
        // convert the protocol failure into UNKNOWN, so the refusal is visible
        // instead of being flattened into an outcome.
        await expect(
          adapter.execute({
            capabilityId: "test.read",
            arguments: {},
            authority: { principal: "alice@example.com" },
            executionClass: "READ",
          }),
        ).rejects.toThrow(vector.error_contains ?? "");
        return;
      }

      const outcome = await adapter.execute({
        capabilityId: "test.counter.increment",
        arguments: {},
        authority: { principal: "alice@example.com" },
        executionClass: "MUTATION",
        idempotencyKey: "outcome-conformance",
      });
      expect(outcome.status).toBe(vector.nemo_status);
    });
  }
});
