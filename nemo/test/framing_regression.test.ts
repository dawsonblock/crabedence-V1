import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { ExecutionApiServer, type ExecutionApiRequest, type ExecutionApiResponse } from "../adapters/crabedence/server";
import { CrabedenceClient } from "../adapters/crabedence/adapter";
import { connect, type Socket } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// Helper: send a raw frame with exact byte length (for Unicode tests)
function sendRawFrame(socketPath: string, payload: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath, () => {
      const header = Buffer.alloc(4);
      header.writeUInt32BE(payload.byteLength, 0);
      socket.write(header);
      socket.write(payload);
    });
    const chunks: Buffer[] = [];
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.on("end", () => {
      const buf = Buffer.concat(chunks);
      if (buf.length < 4) {
        reject(new Error("response too short"));
        return;
      }
      const respLen = buf.readUInt32BE(0);
      resolve(buf.subarray(4, 4 + respLen));
    });
    socket.on("error", reject);
  });
}

describe("Unicode framing regression", () => {
  let server: ExecutionApiServer;
  let socketPath: string;
  let tmpDir: string;
  let callCount = 0;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "nemo-unicode-"));
    socketPath = join(tmpDir, "test.sock");
    callCount = 0;
    server = new ExecutionApiServer(
      async (req) => {
        callCount++;
        return {
          status: "SUCCEEDED" as const,
          result: req.arguments,
        };
      },
      socketPath,
    );
    server.start();
  });

  afterEach(() => {
    server.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("round-trips emoji in arguments", async () => {
    const body = "Hello 🙂 World";
    const request: ExecutionApiRequest = {
      capability: "test.echo",
      arguments: { body },
      authority: { principal: "alice", authority_ref: "grant_1" },
    };
    const payload = Buffer.from(JSON.stringify(request), "utf-8");
    const respBuf = await sendRawFrame(socketPath, payload);
    const resp = JSON.parse(respBuf.toString("utf-8")) as ExecutionApiResponse;
    expect(resp.status).toBe("SUCCEEDED");
    expect((resp.result as { body: string }).body).toBe(body);
  });

  it("round-trips CJK characters", async () => {
    const body = "你好世界";
    const request: ExecutionApiRequest = {
      capability: "test.echo",
      arguments: { body },
      authority: { principal: "alice", authority_ref: "grant_1" },
    };
    const payload = Buffer.from(JSON.stringify(request), "utf-8");
    const respBuf = await sendRawFrame(socketPath, payload);
    const resp = JSON.parse(respBuf.toString("utf-8")) as ExecutionApiResponse;
    expect(resp.status).toBe("SUCCEEDED");
    expect((resp.result as { body: string }).body).toBe(body);
  });

  it("round-trips accented text", async () => {
    const body = "café résumé naïve";
    const request: ExecutionApiRequest = {
      capability: "test.echo",
      arguments: { body },
      authority: { principal: "alice", authority_ref: "grant_1" },
    };
    const payload = Buffer.from(JSON.stringify(request), "utf-8");
    const respBuf = await sendRawFrame(socketPath, payload);
    const resp = JSON.parse(respBuf.toString("utf-8")) as ExecutionApiResponse;
    expect(resp.status).toBe("SUCCEEDED");
    expect((resp.result as { body: string }).body).toBe(body);
  });

  it("round-trips mixed Unicode", async () => {
    const body = "Hello 🙂 你好 café résumé 🎉";
    const request: ExecutionApiRequest = {
      capability: "test.echo",
      arguments: { body },
      authority: { principal: "alice", authority_ref: "grant_1" },
    };
    const payload = Buffer.from(JSON.stringify(request), "utf-8");
    const respBuf = await sendRawFrame(socketPath, payload);
    const resp = JSON.parse(respBuf.toString("utf-8")) as ExecutionApiResponse;
    expect(resp.status).toBe("SUCCEEDED");
    expect((resp.result as { body: string }).body).toBe(body);
  });
});

describe("Concurrent idempotency regression", () => {
  let server: ExecutionApiServer;
  let socketPath: string;
  let tmpDir: string;
  let callCount = 0;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "nemo-concurrent-"));
    socketPath = join(tmpDir, "test.sock");
    callCount = 0;
  });

  afterEach(() => {
    server.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("executes handler exactly once for 10 concurrent identical requests", async () => {
    // Handler that takes time (simulates real work)
    server = new ExecutionApiServer(
      async () => {
        callCount++;
        // Simulate work so concurrent requests overlap
        await new Promise((r) => setTimeout(r, 50));
        return {
          status: "SUCCEEDED" as const,
          result: { count: callCount },
        };
      },
      socketPath,
    );
    await server.start();

    const client = new CrabedenceClient(socketPath, 5000);
    const request = {
      capability: "test.mutation",
      arguments: { value: 1 },
      authority: { principal: "alice", authority_ref: "grant_1" },
      idempotency_key: "concurrent-key-001",
    };

    // Send 10 concurrent requests with the same idempotency key
    const results = await Promise.allSettled(
      Array.from({ length: 10 }, () => client.execute(request)),
    );

    // Handler should be called exactly once
    expect(callCount).toBe(1);

    // All requests should get a response (SUCCEEDED or UNKNOWN for in-flight)
    const succeeded = results.filter(
      (r) => r.status === "fulfilled" && r.value.status === "SUCCEEDED",
    );
    const unknown = results.filter(
      (r) => r.status === "fulfilled" && r.value.status === "UNKNOWN",
    );
    expect(succeeded.length + unknown.length).toBe(10);
  });
});
