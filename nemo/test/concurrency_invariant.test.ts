/**
 * Concurrent transport convergence, hammered.
 *
 * Scope: this exercises the NEMO transport path against the in-memory
 * bridge — client behavior, IN_FLIGHT mapping, reservation convergence,
 * and the observation log that classifies a failure as "two executions"
 * vs. "one execution, wrong observed state". The bridge is a test
 * double: it has no durable ledger, no leases, and no receipts.
 *
 * The DURABLE single-dispatch qualification is the Go/PostgreSQL test
 * `TestLiveConcurrentIdenticalMutationSingleDispatch`
 * (internal/execution/concurrent_live_test.go), which proves one
 * durable effect identity and at most one provider dispatch through the
 * real store. Do not overclaim what this file establishes.
 *
 * The invariant under test here:
 *
 *   N identical concurrent requests
 *     -> exactly 1 reservation owner
 *     -> at most 1 handler dispatch
 *     -> exactly 1 terminal outcome
 *     -> all callers observe that outcome or a truthful in-flight state
 *
 * Every iteration randomizes arrival order and provider timing, because
 * the failure modes this guards against only appear under particular
 * interleavings.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { afterEach, describe, expect, it } from "vitest";

import { CrabedenceClient, ExecutionApiServer } from "../adapters/crabedence/index";

const ITERATIONS = Number(process.env.NEMO_HAMMER_ITERATIONS ?? 100);
const CONCURRENCY = Number(process.env.NEMO_HAMMER_CONCURRENCY ?? 8);
const TEST_TIMEOUT_MS = Number(process.env.NEMO_HAMMER_TIMEOUT_MS ?? 120_000);

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const jitter = (maxMs: number) => sleep(Math.floor(Math.random() * (maxMs + 1)));

interface IterationDiagnostics {
  readonly iteration: number;
  readonly dispatchCount: number;
  readonly statuses: string[];
  readonly results: unknown[];
  readonly observations: unknown[];
}

describe("Concurrent transport convergence (hammer)", () => {
  const directories: string[] = [];

  afterEach(() => {
    for (const directory of directories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it(
    `${ITERATIONS} iterations x ${CONCURRENCY} identical concurrent mutations converge on one terminal outcome`,
    async () => {
      const failures: IterationDiagnostics[] = [];

      for (let iteration = 0; iteration < ITERATIONS; iteration++) {
        const directory = mkdtempSync(join(tmpdir(), "nemo-hammer-"));
        directories.push(directory);
        const socketPath = join(directory, "hammer.sock");
        const key = `hammer-${iteration}-${Math.random().toString(16).slice(2)}`;

        let dispatchCount = 0;
        const server = new ExecutionApiServer(async () => {
          dispatchCount++;
          // Randomized provider work: followers that arrive during this
          // window must observe IN_FLIGHT, never a second dispatch.
          await jitter(4);
          return {
            status: "SUCCEEDED" as const,
            result: { effect_id: `effect_${key}`, dispatch: dispatchCount },
            execution: { provider: "hammer", run_id: `run_${key}` },
          };
        }, socketPath);
        await server.start();

        const client = new CrabedenceClient(socketPath, 10_000);
        const request = {
          capability: "test.mutation",
          arguments: { value: iteration },
          authority: { principal: "alice@example.com", authority_ref: "grant_hammer" },
          execution_class: "MUTATION",
          idempotency_key: key,
        };

        try {
          // Randomized arrival order: launch jitter shuffles which caller
          // wins the reservation.
          const responses = await Promise.all(
            Array.from({ length: CONCURRENCY }, async () => {
              await jitter(3);
              return client.execute(request);
            }),
          );

          const statuses = responses.map((response) => response.status);
          const succeeded = responses.filter((response) => response.status === "SUCCEEDED");
          const inFlight = responses.filter((response) => response.status === "UNKNOWN");
          const observations = server.observations();
          const problem = (message: string): string => {
            failures.push({
              iteration,
              dispatchCount,
              statuses,
              results: responses.map((response) => response.result),
              observations,
            });
            return message;
          };

          let violation: string | null = null;

          // Exactly one provider dispatch, exactly one reservation owner.
          if (dispatchCount !== 1) violation = problem(`provider dispatches = ${dispatchCount}`);
          else if (observations.filter((o) => o.dispatched).length !== 1)
            violation = problem("observation log has != 1 dispatched request");
          else if (observations.filter((o) => o.reservation === "NEW").length !== 1)
            violation = problem("observation log has != 1 NEW reservation");
          // Every other caller observed IN_FLIGHT or the terminal replay.
          else if (succeeded.length + inFlight.length !== responses.length)
            violation = problem(`unexpected statuses: ${statuses.join(",")}`);
          else if (succeeded.length < 1) violation = problem("no caller observed the terminal outcome");
          // Exactly one terminal outcome: every SUCCEEDED result is identical.
          else {
            const [terminal] = succeeded;
            const divergent = succeeded.find(
              (response) => JSON.stringify(response.result) !== JSON.stringify(terminal.result),
            );
            if (divergent) violation = problem("callers observed different terminal results");
          }

          // Convergence: a retry after terminalization replays the same
          // terminal outcome and never dispatches again.
          if (!violation) {
            const retry = await client.execute(request);
            if (retry.status !== "SUCCEEDED")
              violation = problem(`retry status = ${retry.status}, want SUCCEEDED`);
            else if (
              JSON.stringify(retry.result) !==
              JSON.stringify(responses.find((r) => r.status === "SUCCEEDED")?.result)
            )
              violation = problem("retry did not replay the terminal result");
            else if (dispatchCount !== 1)
              violation = problem(`retry dispatched again (dispatches = ${dispatchCount})`);
          }

          if (violation) {
            // Keep the loop hammering so one iteration reports a full picture.
            console.error(`hammer iteration ${iteration}: ${violation}`);
          }
        } finally {
          await server.stop();
        }
      }

      expect(failures).toEqual([]);
    },
    TEST_TIMEOUT_MS,
  );
});
