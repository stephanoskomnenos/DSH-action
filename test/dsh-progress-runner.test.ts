import { afterEach, describe, expect, it } from "vitest";

import { DshAbortedError, DshOutputLimitError, DshTimeoutError } from "../src/dsh/errors.js";
import { runDsh } from "../src/dsh/runner.js";
import { createDshFixtureManager, fakeProxy, request } from "./helpers/dsh-runner-fixtures.js";

const manager = createDshFixtureManager();
afterEach(manager.dispose);
const output = {
  protocolVersion: 1,
  operation: "review",
  state: "final",
  summary: "No actionable findings.",
  findings: [],
};
const raw = [
  { type: "session", sessionId: "private-session", cwd: "/private/source" },
  { type: "status", phase: "step_start", turn: 0, step: 0 },
  { type: "thinking", text: "PRIVATE_THINKING" },
  { type: "tool_call", callId: "private-call", tool: "read", input: { path: "private.txt" } },
  { type: "tool_result", callId: "private-call", status: "completed", result: "PRIVATE_SOURCE" },
  { type: "status", phase: "step_end", turn: 0, step: 0 },
  { type: "final", text: JSON.stringify(output) },
]
  .map((event) => JSON.stringify(event))
  .join("\n");

describe("DSH progress lifecycle", () => {
  it.each([false, true])(
    "preserves raw output and exact final result with progress=%s",
    async (enabled) => {
      const fixture = await manager.fixtures();
      const logs: string[] = [];
      const result = await runDsh(
        request({
          workspacePath: fixture.workspace,
          dshExecutable: fixture.executable,
          progressLog: enabled,
        }),
        {
          assetsDirectory: fixture.assets,
          temporaryDirectory: fixture.root,
          startProxy: () => Promise.resolve(fakeProxy()),
          info: (line) => logs.push(line),
          executeProcess: (_spec, limits) => {
            expect(limits.onStdout !== undefined).toBe(enabled);
            const bytes = Buffer.from(raw);
            for (let index = 0; index < bytes.length; index += 7)
              limits.onStdout?.(bytes.subarray(index, index + 7));
            if (enabled) expect(logs.join("\n")).toContain("event=tool_call tool=read");
            expect(logs.join("\n")).not.toContain("outcome=validated");
            return Promise.resolve({ stdout: raw, stderr: "", exitCode: 0, signal: null });
          },
        },
      );
      expect(result.output).toEqual(output);
      expect(result.rawStdout).toBe(raw);
      if (enabled) {
        expect(logs.at(-1)).toContain("event=worker_end outcome=validated");
        expect(logs.join("\n")).toMatch(/PRIVATE_THINKING/u);
        expect(logs.join("\n")).toContain("private.txt");
        expect(logs.join("\n")).toContain("PRIVATE_SOURCE");
        expect(logs.join("\n")).toContain("No actionable findings.");
      } else expect(logs).toEqual([]);
    },
  );

  it.each([
    { kind: "timeout", error: new DshTimeoutError(1), code: "DSH_TIMEOUT", outcome: "timeout" },
    { kind: "cancel", error: new DshAbortedError(), code: "DSH_ABORTED", outcome: "cancelled" },
    {
      kind: "limit",
      error: new DshOutputLimitError("stdout", 1),
      code: "DSH_OUTPUT_LIMIT",
      outcome: "output_limit",
    },
    { kind: "nonzero", code: "DSH_PROCESS_FAILED", outcome: "failed" },
    { kind: "malformed", code: "DSH_MALFORMED_OUTPUT", outcome: "failed" },
    { kind: "secret", code: "DSH_CREDENTIAL_LEAK", outcome: "failed" },
  ])("never treats streamed final as success on $kind", async ({ kind, error, code, outcome }) => {
    const fixture = await manager.fixtures();
    const logs: string[] = [];
    await expect(
      runDsh(
        request({
          workspacePath: fixture.workspace,
          dshExecutable: fixture.executable,
          progressLog: true,
        }),
        {
          assetsDirectory: fixture.assets,
          temporaryDirectory: fixture.root,
          startProxy: () => Promise.resolve(fakeProxy()),
          info: (line) => logs.push(line),
          executeProcess: (_spec, limits) => {
            const stdout =
              raw +
              (kind === "malformed" ? "\n{broken" : "") +
              (kind === "secret" ? '\n{"type":"text","text":"controller-real-key"}' : "");
            limits.onStdout?.(Buffer.from(stdout));
            if (error !== undefined) return Promise.reject(error);
            return Promise.resolve({
              stdout,
              stderr: "",
              exitCode: kind === "nonzero" ? 1 : 0,
              signal: null,
            });
          },
        },
      ),
    ).rejects.toMatchObject({ code });
    expect(logs.join("\n")).toContain("event=step_start");
    expect(logs.at(-1)).toContain(`event=worker_end outcome=${outcome}`);
    expect(logs.join("\n")).not.toMatch(/outcome=validated|controller-real-key/u);
  });
});
