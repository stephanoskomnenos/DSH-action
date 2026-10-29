import { stripVTControlCharacters } from "node:util";

import { redactSecrets, stripInvisibleCharacters } from "../security/redaction.js";
import { DshAbortedError, DshOutputLimitError, DshTimeoutError } from "./errors.js";

const DEFAULT_OUTPUT_BYTES = 2 * 1024 * 1024;
const phases = new Set(["turn_start", "step_start", "step_end", "turn_end"]);
const credentialField =
  /^(?:authorization|proxy[-_]?authorization|(?:set[-_]?)?cookie|(?:.*[-_])?(?:password|passwd|passphrase|secret|token|api[-_]?key|private[-_]?key|access[-_]?key|credentials?))$/iu;

function sensitiveField(key: string): boolean {
  return credentialField.test(key.replace(/([a-z])([A-Z])/gu, "$1_$2"));
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Detailed display only; raw stdout and terminal validation stay authoritative. */
export class DshProgressObserver {
  private readonly startedAt: number;
  private pending: Buffer[] = [];
  private pendingBytes = 0;
  private droppingLine = false;
  private finished = false;
  private emittedBytes = 0;
  private limited = false;
  private lastEvent = "worker_start";
  private lastEventAt: number;
  private readonly calls = new Map<string, string>();

  public constructor(
    private readonly log: (message: string) => void,
    private readonly secrets: readonly string[],
    private readonly now: () => number = Date.now,
    private readonly maxBytes = DEFAULT_OUTPUT_BYTES,
  ) {
    this.startedAt = now();
    this.lastEventAt = this.startedAt;
    this.emit("event=worker_start");
  }

  private elapsed(since: number): number {
    return Math.max(0, Math.floor(this.now() - since));
  }

  private redact(text: string): string {
    let safe = text;
    for (const secret of this.secrets) {
      if (secret !== "") {
        safe = safe.replaceAll(secret, "[REDACTED]");
        safe = safe.replaceAll(encodeURIComponent(secret), "[REDACTED]");
      }
    }
    safe = stripInvisibleCharacters(stripVTControlCharacters(safe));
    safe = redactSecrets(safe)
      .replace(/https?:\/\/[^\s<>"']+/giu, (value) => {
        try {
          const url = new URL(value);
          url.username = "";
          url.password = "";
          for (const key of [...url.searchParams.keys()]) {
            if (sensitiveField(key) || /^(?:key|auth|sig|signature|x-amz-signature)$/iu.test(key))
              url.searchParams.set(key, "[REDACTED]");
          }
          if (/(?:token|secret|password|key|signature)=/iu.test(url.hash)) url.hash = "[REDACTED]";
          return url.toString();
        } catch {
          return value.replace(/^(https?:\/\/)[^/@]+@/iu, "$1[REDACTED]@");
        }
      })
      .replace(
        /((?:authorization|proxy-authorization)\s*[:=]\s*)(?:bearer|basic|token)\s+[^\s,;]+/giu,
        "$1[REDACTED]",
      )
      .replace(
        /(?<![\w.-])(["']?(?:[\w.-]*[_-])?(?:password|passwd|passphrase|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|cookie)["']?\s*[:=]\s*)(?:"(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;}&]+)/giu,
        "$1[REDACTED]",
      );
    // Strip terminal controls before the last secret check so they cannot split a key.
    for (const secret of this.secrets) {
      const plain = stripInvisibleCharacters(stripVTControlCharacters(secret));
      if (plain !== "") safe = safe.replaceAll(plain, "[REDACTED]");
    }
    return safe;
  }

  private display(value: unknown): string {
    if (value === undefined) return "";
    if (typeof value === "string") {
      try {
        const parsed: unknown = JSON.parse(value);
        if (object(parsed) || Array.isArray(parsed)) return this.display(parsed);
      } catch {
        // Most DSH text and tool results are ordinary text, not JSON.
      }
      return this.redact(value);
    }
    return JSON.stringify(
      value,
      (key, entry: unknown) =>
        sensitiveField(key) ? "[REDACTED]" : typeof entry === "string" ? this.redact(entry) : entry,
      2,
    );
  }

  private emit(fields: string, body = "", terminal = false): void {
    if (!terminal && this.limited) return;
    const prefix = `[DSH progress] elapsedMs=${String(this.elapsed(this.startedAt))} `;
    // Prefix EVERY physical line; untrusted text must not become an Actions command.
    const text = this.redact(fields + (body === "" ? "" : `\n${body}`));
    let rendered = text
      .split(/\r\n?|\n|\u2028|\u2029/u)
      .map((line) => prefix + line)
      .join("\n");
    if (!terminal) {
      const remaining = Math.max(0, this.maxBytes - this.emittedBytes);
      const bytes = Buffer.from(rendered, "utf8");
      if (bytes.length > remaining) {
        this.limited = true;
        rendered = bytes
          .subarray(0, remaining)
          .toString("utf8")
          .replace(/\uFFFD$/u, "");
      }
      this.emittedBytes += Buffer.byteLength(rendered, "utf8");
    }
    if (rendered === "") return;
    try {
      this.log(rendered);
    } catch {
      // Logging must not change execution, failure classification or the result.
    }
  }

  private line(): void {
    if (this.droppingLine || this.pendingBytes === 0) return;
    try {
      const data: unknown = JSON.parse(
        Buffer.concat(this.pending, this.pendingBytes).toString("utf8"),
      );
      if (!object(data) || typeof data.type !== "string") return;
      let label = data.type;
      let fields = `event=${label}`;
      let body = "";
      if (data.type === "status" && typeof data.phase === "string" && phases.has(data.phase)) {
        label = data.phase;
        fields = `event=${label} turn=${String(data.turn)}`;
        if (data.step !== undefined) fields += ` step=${this.display(data.step)}`;
        body = this.display({
          ...(data.reason === undefined ? {} : { reason: data.reason }),
          ...(data.usage === undefined ? {} : { usage: data.usage }),
        });
        if (body === "{}") body = "";
      } else if (data.type === "tool_call" && typeof data.tool === "string") {
        fields += ` tool=${data.tool}`;
        if (typeof data.callId === "string") {
          this.calls.set(data.callId, data.tool);
          fields += ` call=${data.callId}`;
        }
        if (data.input !== undefined) body = `Input:\n${this.display(data.input)}`;
      } else if (data.type === "tool_result") {
        if (typeof data.callId === "string") {
          const tool = this.calls.get(data.callId);
          if (tool !== undefined) fields += ` tool=${tool}`;
          fields += ` call=${data.callId}`;
          this.calls.delete(data.callId);
        }
        fields += ` status=${String(data.status)}`;
        body = this.display(data.result);
      } else if (
        ["thinking", "text", "final"].includes(data.type) &&
        typeof data.text === "string"
      ) {
        // These are DSH's committed messages, never this Controller's reasoning.
        // A displayed final is still unvalidated until finish() says otherwise.
        body = this.display(data.text);
      } else body = this.display(data);
      if (data.truncated === true) fields += " truncated=true";
      this.lastEvent =
        phases.has(label) ||
        [
          "session",
          "status",
          "thinking",
          "text",
          "tool_call",
          "tool_result",
          "final",
          "error",
        ].includes(label)
          ? label
          : "other";
      this.lastEventAt = this.now();
      this.emit(fields, body);
    } catch {
      // A malformed display event never changes the authoritative parser.
    }
  }

  /** Byte framing preserves UTF-8 split across chunks and the process byte budget. */
  public observe(chunk: Buffer): void {
    if (this.finished || this.limited) return;
    let start = 0;
    while (start < chunk.length) {
      const newline = chunk.indexOf(10, start);
      const end = newline === -1 ? chunk.length : newline;
      const bytes = end - start;
      if (!this.droppingLine) {
        if (this.pendingBytes + bytes > this.maxBytes) {
          this.pending = [];
          this.pendingBytes = 0;
          this.droppingLine = true;
        } else if (bytes > 0) {
          this.pending.push(Buffer.from(chunk.subarray(start, end)));
          this.pendingBytes += bytes;
        }
      }
      if (newline === -1) break;
      this.line();
      this.pending = [];
      this.pendingBytes = 0;
      this.droppingLine = false;
      start = newline + 1;
    }
  }

  /** Called only after the worker owner's validation/evidence/session checks. */
  public finish(error?: unknown): void {
    if (this.finished) return;
    this.finished = true;
    this.line();
    this.pending = [];
    this.pendingBytes = 0;
    this.calls.clear();
    const outcome =
      error === undefined
        ? "validated"
        : error instanceof DshTimeoutError
          ? "timeout"
          : error instanceof DshAbortedError
            ? "cancelled"
            : error instanceof DshOutputLimitError
              ? "output_limit"
              : "failed";
    this.emit(
      `event=worker_end outcome=${outcome} last=${this.lastEvent} idleMs=${String(this.elapsed(this.lastEventAt))} logsLimited=${String(this.limited)}`,
      "",
      true,
    );
  }
}
