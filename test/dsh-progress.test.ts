import { describe, expect, it, vi } from "vitest";

import { DshAbortedError, DshOutputLimitError, DshTimeoutError } from "../src/dsh/errors.js";
import { DshProgressObserver } from "../src/dsh/progress.js";

const event = (value: unknown, ending = "\n"): Buffer =>
  Buffer.from(JSON.stringify(value) + ending);
const status = (phase = "step_start", step = 0) => ({ type: "status", phase, turn: 0, step });
const textOf = (logs: readonly string[]): string => logs.join("\n");

function fixture(secrets: readonly string[] = [], maxBytes?: number) {
  const logs: string[] = [];
  const observer = new DshProgressObserver(
    (line) => logs.push(line),
    secrets,
    () => 0,
    maxBytes,
  );
  return { logs, observer };
}

function expectPrefixed(logs: readonly string[]): void {
  for (const line of textOf(logs).split(/\r\n?|\n|\u2028|\u2029/u)) {
    expect(line).toMatch(/^\[DSH progress\] elapsedMs=\d+ /u);
  }
}

describe("DSH detailed progress observer", () => {
  it("reassembles UTF-8 byte chunks and displays committed text and status details", () => {
    const { logs, observer } = fixture();
    const bytes = Buffer.concat([
      event({ ...status(), reason: "正在检查 🐈", usage: { inputTokens: 123 } }),
      event({ type: "text", text: "读取源码 中文 🐈" }),
    ]);
    for (const byte of bytes) observer.observe(Buffer.from([byte]));
    observer.finish();
    expect(textOf(logs)).toContain("正在检查 🐈");
    expect(textOf(logs)).toContain("读取源码 中文 🐈");
    expect(textOf(logs)).toContain('"inputTokens": 123');
    expect(textOf(logs)).not.toContain("�");
    expectPrefixed(logs);
  });

  it("handles CRLF, blanks and a final line without a newline", () => {
    const { logs, observer } = fixture();
    observer.observe(
      Buffer.concat([
        Buffer.from("\r\n\n"),
        event(status("turn_start"), "\r\n"),
        event(status("step_start", 1), "\r\n"),
        event(status("step_end", 1), ""),
      ]),
    );
    expect(logs).toHaveLength(3);
    observer.finish(new DshTimeoutError(100));
    expect(logs).toHaveLength(5);
    expect(logs[3]).toContain("event=step_end turn=0 step=1");
    expect(logs[4]).toContain("outcome=timeout last=step_end");
  });

  it("ignores malformed JSON and non-event values without changing settlement", () => {
    const { logs, observer } = fixture();
    observer.observe(Buffer.from("broken JSON\n{\n"));
    for (const value of [null, true, 123, "plain text", [status()], {}, { type: 123 }]) {
      observer.observe(event(value));
    }
    observer.observe(event(status()));
    observer.finish(new Error("controller failure not published"));
    expect(logs).toHaveLength(3);
    expect(logs[2]).toContain("outcome=failed");
    expect(textOf(logs)).not.toContain("controller failure not published");
  });

  it("shows session, truncated, error and unfamiliar events as safely serialized data", () => {
    const { logs, observer } = fixture();
    for (const value of [
      { type: "session", sessionId: "session-1", cwd: "/workspace" },
      { type: "status", truncated: true },
      { type: "error", message: "tool permission denied" },
      { type: "future_event", detail: "future detail" },
    ])
      observer.observe(event(value));
    observer.finish();
    for (const expected of [
      "session-1",
      "/workspace",
      "truncated=true",
      "tool permission denied",
      "future detail",
    ]) {
      expect(textOf(logs)).toContain(expected);
    }
    expectPrefixed(logs);
  });

  it("shows actual tool names, call IDs, arguments, results and errors", () => {
    const { logs, observer } = fixture();
    observer.observe(
      event({
        type: "tool_call",
        tool: "mcp__custom__lookup",
        callId: "call-7",
        input: { file: "src/index.ts", query: "find entrypoint" },
      }),
    );
    observer.observe(
      event({
        type: "tool_result",
        callId: "call-7",
        status: "error",
        result: "No entrypoint found",
      }),
    );
    observer.finish();
    expect(textOf(logs)).toContain("event=tool_call tool=mcp__custom__lookup call=call-7");
    expect(textOf(logs)).toContain('"file": "src/index.ts"');
    expect(textOf(logs)).toContain("find entrypoint");
    expect(textOf(logs)).toContain(
      "event=tool_result tool=mcp__custom__lookup call=call-7 status=error",
    );
    expect(textOf(logs)).toContain("No entrypoint found");
  });

  it("shows DSH thinking, text and final content without claiming success before validation", () => {
    const { logs, observer } = fixture();
    for (const type of ["thinking", "text", "final"])
      observer.observe(event({ type, text: `DSH ${type} content` }));
    expect(textOf(logs)).toContain("DSH thinking content");
    expect(textOf(logs)).toContain("DSH text content");
    expect(textOf(logs)).toContain("DSH final content");
    expect(textOf(logs)).not.toContain("outcome=validated");
    observer.finish(new DshTimeoutError(100));
    expect(textOf(logs)).toContain("outcome=timeout");
    expect(textOf(logs)).not.toContain("outcome=validated");
  });

  it("redacts nested credential fields while preserving ordinary arguments and results", () => {
    const { logs, observer } = fixture();
    observer.observe(
      event({
        type: "tool_call",
        tool: "custom",
        input: {
          file: "README.md",
          headers: { Authorization: "Bearer HEADER_SECRET", Cookie: "COOKIE_SECRET" },
          nested: [
            {
              apiKey: "API_SECRET",
              accessToken: "ACCESS_SECRET",
              password: "PASSWORD_SECRET",
              private_key: "PRIVATE_SECRET",
              ordinary: "visible",
            },
          ],
        },
      }),
    );
    observer.observe(
      event({
        type: "tool_result",
        status: "completed",
        result: JSON.stringify({ clientSecret: "CLIENT_SECRET", result: "kept result" }),
      }),
    );
    observer.finish();
    for (const secret of [
      "HEADER_SECRET",
      "COOKIE_SECRET",
      "API_SECRET",
      "ACCESS_SECRET",
      "PASSWORD_SECRET",
      "PRIVATE_SECRET",
      "CLIENT_SECRET",
    ])
      expect(textOf(logs)).not.toContain(secret);
    for (const visible of ["README.md", "visible", "kept result", "[REDACTED]"])
      expect(textOf(logs)).toContain(visible);
  });

  it("redacts known credentials in names, IDs, text, escaped JSON and control-split strings", () => {
    const secret = "fixture-credential-value";
    const { logs, observer } = fixture([secret]);
    observer.observe(
      event({ type: "tool_call", tool: secret, callId: secret, input: { ordinary: secret } }),
    );
    observer.observe(Buffer.from('{"type":"text","text":"\\u0066ixture-credential-value"}\n'));
    observer.observe(
      event({
        type: "tool_result",
        status: "completed",
        result: '{"ordinary":"\\u0066ixture-credential-value"}',
      }),
    );
    observer.observe(
      event({ type: "thinking", text: "fixture-\u001b[31mcredential\u001b[0m-value" }),
    );
    observer.finish();
    expect(textOf(logs)).not.toContain(secret);
    expect(textOf(logs)).not.toContain("\\u0066ixture");
    expect(textOf(logs)).toContain("[REDACTED]");
    expectPrefixed(logs);
  });

  it("redacts authorization text, URL credentials, token query values and fragments", () => {
    const { logs, observer } = fixture();
    observer.observe(
      event({
        type: "text",
        text: [
          "Authorization: Bearer AUTH_SECRET",
          "password=PASSWORD_SECRET",
          "https://USER_SECRET:PASS_SECRET@example.test/path?token=QUERY_SECRET&x-amz-signature=SIG_SECRET&view=public",
          "https://example.test/#token=FRAGMENT_SECRET",
        ].join("\n"),
      }),
    );
    observer.finish();
    for (const secret of [
      "AUTH_SECRET",
      "PASSWORD_SECRET",
      "USER_SECRET",
      "PASS_SECRET",
      "QUERY_SECRET",
      "SIG_SECRET",
      "FRAGMENT_SECRET",
    ])
      expect(textOf(logs)).not.toContain(secret);
    expect(textOf(logs)).toContain("view=public");
    expect(textOf(logs)).toContain("example.test/path");
  });

  it("redacts percent-encoded known credentials in arbitrary URL fields", () => {
    const secret = "fixture/private credential";
    const encoded = encodeURIComponent(secret);
    const { logs, observer } = fixture([secret]);
    observer.observe(
      event({ type: "text", text: `https://example.test/${encoded}?ordinary=${encoded}` }),
    );
    observer.finish();
    expect(textOf(logs)).not.toContain(secret);
    expect(textOf(logs)).not.toContain(encoded);
    expect(textOf(logs)).toContain("example.test/");
  });

  it("prefixes every physical line and strips terminal controls in all event fields", () => {
    const { logs, observer } = fixture();
    const attack =
      "\r\n::warning::not-an-annotation\r::set-output name=x::bad\u2028::error::bad\u2029\u001b[2K\u001b[31mvisible\u001b[0m";
    observer.observe(event({ type: "text", text: attack }));
    observer.observe(
      event({ type: "tool_call", tool: attack, callId: attack, input: { text: attack } }),
    );
    observer.observe(event({ ...status(), phase: attack, turn: attack, step: attack }));
    observer.finish();
    expect(textOf(logs)).toContain("not-an-annotation");
    expect(textOf(logs)).not.toContain("\u001b");
    expectPrefixed(logs);
  });

  it("retains a final event larger than the old 64-KiB display limit", () => {
    const { logs, observer } = fixture();
    const body = "begin-" + "x".repeat(70_000) + "-end";
    const bytes = event({ type: "final", text: body });
    for (let offset = 0; offset < bytes.length; offset += 127)
      observer.observe(bytes.subarray(offset, offset + 127));
    observer.finish();
    expect(textOf(logs)).toContain(body);
    expect(textOf(logs)).toContain("logsLimited=false");
  });

  it("does not impose the old 200-event cap", () => {
    const { logs, observer } = fixture();
    observer.observe(
      Buffer.concat(Array.from({ length: 500 }, (_, step) => event(status("step_start", step)))),
    );
    observer.finish();
    expect(logs).toHaveLength(502);
    expect(textOf(logs)).toContain("step=499");
    expect(logs.at(-1)).toContain("logsLimited=false");
  });

  it("bounds displayed bytes after redaction while always retaining the terminal summary", () => {
    const secret = "DO_NOT_LEAK_THIS_CREDENTIAL";
    const { logs, observer } = fixture([secret], 220);
    observer.observe(event({ type: "text", text: `start ${secret}\n${"x".repeat(90)}` }));
    observer.observe(event(status("turn_end")));
    observer.finish(new DshOutputLimitError("stdout", 220));
    expect(logs.at(-1)).toContain("outcome=output_limit");
    expect(logs.at(-1)).toContain("logsLimited=true");
    expect(
      logs.slice(0, -1).reduce((bytes, line) => bytes + Buffer.byteLength(line), 0),
    ).toBeLessThanOrEqual(220);
    expect(textOf(logs)).not.toContain(secret);
    expect(textOf(logs)).not.toContain("DO_NOT_LEAK");
    expect(textOf(logs)).toContain("[REDACTED]");
  });

  it("drops an event exceeding the input byte budget without parsing a partial JSON object", () => {
    const { logs, observer } = fixture([], 200);
    observer.observe(event({ type: "text", text: "x".repeat(300) }, ""));
    observer.finish(new DshOutputLimitError("stdout", 200));
    expect(logs).toHaveLength(2);
    expect(logs[1]).toContain("outcome=output_limit last=worker_start");
  });

  it("keeps the reserved summary bounded even when an unknown event type contains many newlines", () => {
    const { logs, observer } = fixture([], 500);
    observer.observe(event({ type: "unknown\n".repeat(40), text: "detail" }));
    observer.finish();
    expect(Buffer.byteLength(logs.at(-1) ?? "")).toBeLessThan(300);
    expect(logs.at(-1)).toContain("outcome=validated");
  });

  it("reports elapsed and idle settlement time and ignores later events", () => {
    let now = 1_000;
    const logs: string[] = [];
    const observer = new DshProgressObserver(
      (line) => logs.push(line),
      [],
      () => now,
    );
    now = 3_000;
    observer.observe(event(status()));
    now = 31_000;
    observer.finish();
    expect(logs.at(-1)).toContain(
      "elapsedMs=30000 event=worker_end outcome=validated last=step_start idleMs=28000",
    );
    const length = logs.length;
    observer.observe(event(status("turn_end")));
    observer.finish(new Error("late failure"));
    expect(logs).toHaveLength(length);
  });

  it("clamps clock rollback", () => {
    let now = 100;
    const logs: string[] = [];
    const observer = new DshProgressObserver(
      (line) => logs.push(line),
      [],
      () => now,
    );
    now = 50;
    observer.finish();
    expect(logs.at(-1)).toContain("elapsedMs=0");
    expect(logs.at(-1)).toContain("idleMs=0");
  });

  it.each([
    [undefined, "validated"],
    [new DshTimeoutError(100), "timeout"],
    [new DshAbortedError(), "cancelled"],
    [new DshOutputLimitError("combined", 100), "output_limit"],
    [new Error("controller private failure"), "failed"],
    [null, "failed"],
  ])("classifies settlement without exposing Controller error details: %s", (error, outcome) => {
    const { logs, observer } = fixture();
    observer.finish(error);
    observer.finish();
    expect(logs).toHaveLength(2);
    expect(logs[1]).toContain(`outcome=${outcome}`);
    expect(textOf(logs)).not.toContain("controller private failure");
  });

  it("isolates logging exceptions", () => {
    const log = vi.fn(() => {
      throw new Error("logger unavailable");
    });
    expect(() => {
      const observer = new DshProgressObserver(log, [], () => 0);
      observer.observe(event(status()));
      observer.finish();
    }).not.toThrow();
    expect(log).toHaveBeenCalledTimes(3);
  });
});
