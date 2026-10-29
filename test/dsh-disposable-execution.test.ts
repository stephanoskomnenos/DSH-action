import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runDsh } from "../src/dsh/runner.js";
import type { DshProcessSpec } from "../src/dsh/process.js";
import { disposableExecution, effectiveNativeTools } from "../src/dsh/runner-policy.js";
import {
  CONTAINER_LAUNCHER,
  CONTAINER_PACKAGE_ROOT,
  PINNED_NODE_IMAGE,
  createDshFixtureManager,
  fakeProxy,
  networkInspectResult,
  request,
} from "./helpers/dsh-runner-fixtures.js";

const fixtureManager = createDshFixtureManager();
afterEach(fixtureManager.dispose);

describe("disposable task execution", () => {
  it("enables writable scratch, bridge egress and pnpm without inheriting credentials", async () => {
    const fixture = await fixtureManager.fixtures();
    const specs: DshProcessSpec[] = [];
    let patch = "";
    const output = {
      protocolVersion: 1,
      operation: "task",
      state: "final",
      summary: "Tests passed.",
      findings: [],
    };
    const result = await runDsh(
      request({
        operation: "task",
        isolation: "docker",
        containerImage: PINNED_NODE_IMAGE,
        workspacePath: fixture.workspace,
        nativeTools: ["workspace.read", "native.bash"],
      }),
      {
        assetsDirectory: fixture.assets,
        temporaryDirectory: fixture.root,
        environment: {
          PATH: process.env.PATH,
          GITHUB_TOKEN: "github-real-secret",
          CMS_API_KEY: "cms-real-secret",
          DEPLOY_KEY: "deploy-real-secret",
          DEEPSEEK_API_KEY: "model-real-secret",
          NPM_TOKEN: "registry-real-secret",
          RANDOM_PRIVATE_ENV: "private-env",
        },
        startProxy: () => Promise.resolve(fakeProxy()),
        executeProcess: async (spec) => {
          specs.push(spec);
          const inspected = networkInspectResult(spec);
          if (inspected !== undefined) return inspected;
          if (spec.args.includes(CONTAINER_LAUNCHER)) {
            const mount = spec.args.find((arg) => arg.endsWith(`:${CONTAINER_PACKAGE_ROOT}:ro`));
            if (mount === undefined) throw new Error("package mount missing");
            patch = await readFile(
              join(mount.slice(0, -`:${CONTAINER_PACKAGE_ROOT}:ro`.length), "cordis.patch.yml"),
              "utf8",
            );
            await writeFile(join(fixture.workspace, "scratch-result.txt"), "temporary test output");
            return { stdout: JSON.stringify(output), stderr: "", exitCode: 0, signal: null };
          }
          return { stdout: "", stderr: "", exitCode: 0, signal: null };
        },
      },
    );
    expect(result.output).toEqual(output);
    expect(result.isolationReport).toMatchObject({
      workspaceAccess: "read-write",
      networkIsolated: false,
      credentialMediated: true,
    });
    expect(specs.some(({ args }) => args[0] === "network" && args[1] === "create")).toBe(false);
    const worker = specs.find(({ args }) => args.includes(CONTAINER_LAUNCHER));
    expect(worker).toBeDefined();
    expect(worker?.args).toContain(`${fixture.workspace}:/workspace:rw`);
    expect(worker?.args[worker.args.indexOf("--network") + 1]).toBe("bridge");
    expect(worker?.args).toContain("HOME=/workspace/.dsh-home");
    expect(worker?.args).toContain("DSH_HOME=/dsh-home");
    expect(worker?.args).toContain(
      "PATH=/workspace/.dsh-tools/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    expect(worker?.args).toContain("/bin/sh");
    const bootstrap = worker?.args.find((arg) => arg.includes("pnpm@12.14.0"));
    expect(bootstrap).toContain("--ignore-scripts");
    expect(bootstrap).toContain('>&2 && exec "$@"');
    expect(worker?.args).toContain("--read-only");
    expect(worker?.args).toContain("no-new-privileges");
    expect(JSON.stringify(specs)).not.toMatch(/real-secret|private-env|docker\.sock/u);
    expect(patch).toContain('"runtimeName": "bash"');
    expect(patch).toContain('"mode": "workspace-write"');
  });

  it.each([
    { operation: "review" as const, trust: "trusted-read" as const, isolation: "docker" as const },
    { operation: "task" as const, trust: "untrusted" as const, isolation: "docker" as const },
    { operation: "task" as const, trust: "trusted-read" as const, isolation: "none" as const },
  ])("does not grant execution outside trusted Docker read tasks: %j", (overrides) => {
    const value = request({ ...overrides, nativeTools: ["native.bash"] });
    expect(disposableExecution(value)).toBe(false);
    expect(effectiveNativeTools(value)).not.toContain("native.bash");
  });

  it("requires a pinned image before a writable read-task worker starts", async () => {
    await expect(
      runDsh(request({ operation: "task", isolation: "docker", nativeTools: ["native.bash"] })),
    ).rejects.toThrow("immutable");
  });
});
