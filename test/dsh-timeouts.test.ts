import { afterEach, describe, expect, it, vi } from "vitest";

import { PHASE_TIMEOUTS, phaseTimeoutMs, runBestEffortDshCleanup } from "../src/dsh/timeouts.js";

afterEach(() => {
  vi.useRealTimers();
});

describe("DSH phase budgets", () => {
  it("allows a 30-minute Agent turn without extending other phases or the run deadline", () => {
    expect(PHASE_TIMEOUTS.agentTurnMs).toBe(30 * 60_000);
    expect(phaseTimeoutMs(60 * 60_000, PHASE_TIMEOUTS.agentTurnMs, () => 0)).toBe(30 * 60_000);
    expect(phaseTimeoutMs(20 * 60_000, PHASE_TIMEOUTS.agentTurnMs, () => 5 * 60_000)).toBe(
      15 * 60_000,
    );
    expect(PHASE_TIMEOUTS.runtimeInstallMs).toBe(5 * 60_000);
    expect(PHASE_TIMEOUTS.extensionInstallMs).toBe(5 * 60_000);
    expect(PHASE_TIMEOUTS.setupMs).toBe(60_000);
    expect(PHASE_TIMEOUTS.validationMs).toBe(10 * 60_000);
    expect(PHASE_TIMEOUTS.cleanupMs).toBe(5_000);
  });

  it("uses the smaller of each phase cap and the total deadline remaining", () => {
    expect(phaseTimeoutMs(1_000_000, PHASE_TIMEOUTS.runtimeInstallMs, () => 100)).toBe(
      PHASE_TIMEOUTS.runtimeInstallMs,
    );
    expect(phaseTimeoutMs(1_000_000, PHASE_TIMEOUTS.extensionInstallMs, () => 999_500)).toBe(500);
    expect(phaseTimeoutMs(1_000_000, PHASE_TIMEOUTS.setupMs, () => 1_000_001)).toBe(0);
  });

  it("bounds and swallows cleanup hangs without losing observability", async () => {
    vi.useFakeTimers();
    const warning = vi.fn();
    const cleanup = runBestEffortDshCleanup(
      [{ label: "proxy", run: () => new Promise(() => undefined) }],
      PHASE_TIMEOUTS.cleanupMs,
      warning,
    );

    await vi.advanceTimersByTimeAsync(PHASE_TIMEOUTS.cleanupMs);
    await expect(cleanup).resolves.toBeUndefined();
    expect(warning).toHaveBeenCalledWith(expect.stringContaining("primary result was preserved"));
  });
});
