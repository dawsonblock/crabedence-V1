/**
 * Crabedence execution bridge.
 *
 * This is the production ExecutionHandler that bridges NeMo's Unix
 * socket server to the Go Crabedence core. It calls `crabbox exec`
 * as a subprocess, passing the execution request as JSON on stdin
 * and reading the JSON response from stdout.
 *
 * The Go `crabbox exec` command owns:
 *   - Authority verification
 *   - Provider dispatch
 *   - RunEvidenceV1 generation
 *   - V3 receipt signing
 *   - Terminal bundle commitment
 *   - PostgreSQL fencing
 *
 * This bridge owns nothing except the subprocess protocol.
 */

import { spawn } from "node:child_process";

import type {
  ExecutionApiRequest,
  ExecutionApiResponse,
  ExecutionHandler,
} from "./server";

// ─── Bridge ──────────────────────────────────────────────────────────

/**
 * Options for the Crabedence bridge.
 */
export interface BridgeOptions {
  /** Path to the crabbox binary. Default: "crabbox". */
  readonly binary?: string;
  /** Working directory for the subprocess. Default: process.cwd(). */
  readonly cwd?: string;
  /** Timeout in milliseconds. Default: 30000. */
  readonly timeoutMs?: number;
}

/**
 * Production bridge from NeMo to Crabedence Go core.
 *
 * Returns an ExecutionHandler function that calls `crabbox exec` as a
 * subprocess:
 *   - Writes ExecutionApiRequest as JSON to stdin
 *   - Reads ExecutionApiResponse as JSON from stdout
 *   - Returns UNKNOWN on timeout (the request may have been dispatched)
 *
 * This handler is intentionally thin. All execution machinery lives
 * in the Go core.
 */
export function createCrabedenceBridge(
  opts: BridgeOptions = {},
): ExecutionHandler {
  const binary = opts.binary ?? "crabbox";
  const cwd = opts.cwd ?? process.cwd();
  const timeoutMs = opts.timeoutMs ?? 30_000;

  return async (request: ExecutionApiRequest): Promise<ExecutionApiResponse> => {
    return new Promise((resolve, reject) => {
      const child = spawn(binary, ["exec"], {
        cwd,
        stdio: ["pipe", "pipe", "pipe"],
      });

      let stdout = "";
      let stderr = "";
      let settled = false;
      let dispatched = false;

      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          dispatched = true;
          try {
            child.kill("SIGTERM");
          } catch {
            // ignore
          }
          // On timeout, the request may have been dispatched.
          // Return UNKNOWN for mutations.
          resolve({
            status: "UNKNOWN",
            error: `bridge timeout after ${timeoutMs}ms`,
          });
        }
      }, timeoutMs);

      child.stdin.on("error", () => {
        // ignore
      });

      child.stdout.on("data", (chunk: Buffer) => {
        stdout += chunk.toString("utf-8");
      });

      child.stderr.on("data", (chunk: Buffer) => {
        stderr += chunk.toString("utf-8");
      });

      child.on("error", (err: Error) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(new Error(`bridge spawn error: ${err.message}`));
        }
      });

      child.on("close", (code: number | null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);

        if (code !== 0 && !dispatched) {
          reject(
            new Error(
              `bridge exited with code ${code}: ${stderr.trim()}`,
            ),
          );
          return;
        }

        try {
          const response = JSON.parse(stdout) as ExecutionApiResponse;
          resolve(response);
        } catch {
          reject(
            new Error(
              `bridge response parse error: ${stdout.slice(0, 200)}`,
            ),
          );
        }
      });

      // Write request to stdin
      try {
        const json = JSON.stringify(request);
        child.stdin.write(json);
        child.stdin.end();
        dispatched = true;
      } catch (err) {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(new Error(`bridge write error: ${(err as Error).message}`));
        }
      }
    });
  };
}
