import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { routeCommand } from "../src/commands/router.js";
import { ControlledComposition } from "../src/dsh/controlled-composition.js";
import { admitDshRun } from "../src/dsh/runner-context.js";
import { buildDshPrompt } from "../src/dsh/prompt.js";
import { request } from "./helpers/dsh-runner-fixtures.js";
import type { DshRunResult } from "../src/dsh/runner-types.js";
import type { PolicyInput } from "../src/security/policy.js";
import { evaluatePolicy } from "../src/security/policy.js";
import { resolveEffectiveTools } from "../src/tools/registry.js";
import { parseToolConfiguration } from "../src/tools/schema.js";
import { createWorkspaceSnapshot } from "../src/write/workspace.js";
import { createAuthorityRevalidator } from "../src/orchestration/authority.js";
import { inputs, permissions, pullRequestContext } from "./helpers.js";
import { githubClientFixture } from "./helpers/github-client.js";

const effects = vi.hoisted(() => ({ write: vi.fn(), answer: vi.fn(() => Promise.resolve(7)) }));
vi.mock("../src/orchestration/write.js", () => ({ executeWrite: effects.write }));
vi.mock("../src/commands/task.js", () => ({ publishTaskAnswer: effects.answer }));
import { prepareWorkspaceOperation } from "../src/orchestration/operation-finalizer.js";

const roots: string[] = [];
afterEach(async () => {
  vi.clearAllMocks();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function policyInput(overrides: Partial<PolicyInput> = {}): PolicyInput {
  return {
    context: pullRequestContext(),
    operation: "task",
    requestedAccess: "read",
    allowWrite: false,
    allowExecution: true,
    permissions: permissions(true),
    ...overrides,
  };
}

function unresolvedPullRequestContext() {
  const context = { ...pullRequestContext() };
  if (context.kind === "entity") delete context.pullRequest;
  return context;
}

const result: DshRunResult = {
  output: {
    protocolVersion: 1,
    operation: "task",
    state: "final",
    summary: "Build inspected",
    findings: [],
  },
  durationMs: 1,
  isolationReport: {
    backend: "docker",
    credentialMediated: true,
    repoToolsEnabled: true,
    processIsolated: true,
    networkIsolated: false,
    workspaceAccess: "read-write",
    extensionProfile: "github-action",
    limitations: [],
  },
};

describe("explicit disposable execution", () => {
  it("grants scratch execution, not repository or GitHub mutation authority", () => {
    const policy = evaluatePolicy(policyInput());
    expect(policy).toMatchObject({ allowed: true, trust: "trusted-read" });
    expect(policy.capabilities).toMatchObject({
      readRepository: true,
      executeRepositoryCode: true,
      modifyWorkspace: true,
      accessNetwork: true,
      commit: false,
      push: false,
      createPullRequest: false,
      manageIssueLabels: false,
      manageIssueAssignees: false,
      updateIssueState: false,
      updatePullRequestMetadata: false,
    });
  });

  it("runs the site's same-repository pull_request_target read task with Bash, never GitHub publication", () => {
    const context = pullRequestContext({
      rawEventName: "pull_request_target",
      isPullRequestTarget: true,
      eventAction: "reopened",
    });
    const configured = inputs({
      command: "task",
      taskAccess: "read",
      allowWrite: false,
      isolation: "docker",
      permissionProfile: "custom",
      allowedTools: ["workspace.read", "workspace.search", "native.web-fetch", "native.bash"],
    });
    const command = routeCommand(context, configured);
    if (command === null) throw new Error("expected explicit task");
    const policy = evaluatePolicy(
      policyInput({
        context,
        operation: command.operation,
        requestedAccess: command.requestedAccess,
        allowWrite: configured.allowWrite,
        allowExecution:
          configured.isolation === "docker" &&
          configured.allowedTools.includes("native.bash") &&
          !configured.disallowedTools.includes("native.bash"),
      }),
    );
    expect(policy.capabilities).toMatchObject({
      executeRepositoryCode: true,
      modifyWorkspace: true,
      commit: false,
      push: false,
      createPullRequest: false,
    });
    const tools = resolveEffectiveTools(configured.allowedTools, configured.toolConfig, policy, {
      permissionProfile: configured.permissionProfile,
      isolation: configured.isolation,
      allowWrite: configured.allowWrite,
    });
    expect(tools.native).toContain("native.bash");
    const composition = new ControlledComposition();
    const admission = admitDshRun(
      request({
        operation: command.operation,
        trust: policy.trust,
        isolation: configured.isolation,
        containerImage: configured.containerImage,
        nativeTools: tools.native,
      }),
      { environment: {} },
      composition,
    );
    expect(admission).toMatchObject({
      workspaceWrite: true,
      network: true,
      disposableExecution: true,
    });
    expect(admission.nativeTools).toContain("native.bash");
    const prompt = buildDshPrompt({
      operation: command.operation,
      trust: policy.trust,
      prompt: "Review the bound PR",
      toolPolicy: composition.promptToolPolicy(admission.nativeTools),
    });
    expect(prompt).toContain("install dependencies with preinstalled pnpm");
    expect(prompt).toContain("modify the disposable workspace");
    expect(prompt).not.toContain("Do not use shell or execute repository code directly");
    expect(
      evaluatePolicy(policyInput({ context, requestedAccess: "write", allowWrite: true })).allowed,
    ).toBe(false);
  });

  it("revalidates the explicit Docker Bash grant and revokes it when actor authority changes", async () => {
    let permission = "write";
    const client = githubClientFixture({
      rest: {
        users: { getByUsername: () => Promise.resolve({ data: { type: "User" } }) },
        repos: { getCollaboratorPermissionLevel: () => Promise.resolve({ data: { permission } }) },
      },
    });
    const configured = inputs({
      allowWrite: false,
      allowedTools: ["native.bash"],
      isolation: "docker",
    });
    const revalidate = createAuthorityRevalidator({
      client,
      context: pullRequestContext(),
      command: {
        operation: "task",
        requestedAccess: "read",
        source: "explicit-input",
        instructions: "Inspect build",
      },
      inputs: configured,
      policy: evaluatePolicy(policyInput()),
      signal: new AbortController().signal,
    });
    await expect(revalidate()).resolves.toBeUndefined();
    permission = "read";
    await expect(revalidate()).rejects.toMatchObject({ code: "POLICY_DENIED" });
  });

  it.each([
    { label: "no explicit opt-in", override: { allowExecution: false } },
    { label: "review", override: { operation: "review" as const } },
    { label: "diagnose", override: { operation: "diagnose" as const } },
    { label: "fix", override: { operation: "fix" as const } },
    { label: "write request", override: { requestedAccess: "write" as const } },
    { label: "untrusted actor", override: { permissions: permissions(false) } },
    { label: "fork", override: { context: pullRequestContext({ fork: true }) } },
    {
      label: "unresolved PR",
      override: { context: unresolvedPullRequestContext() },
    },
    {
      label: "unresolved workflow_run",
      override: { context: pullRequestContext({ rawEventName: "workflow_run" }) },
    },
  ])("does not grant disposable execution for $label", ({ override }) => {
    const policy = evaluatePolicy(policyInput(override));
    expect(policy.capabilities.executeRepositoryCode).toBe(false);
    expect(policy.capabilities.modifyWorkspace).toBe(false);
    expect(policy.capabilities.commit).toBe(false);
    expect(policy.capabilities.push).toBe(false);
  });

  it("admits only requested Bash, not editor, subagent or GitHub mutation capabilities", () => {
    const effective = resolveEffectiveTools(
      ["native.bash", "workspace.edit", "native.subagent", "github.issue.labels.set"],
      parseToolConfiguration('{"schemaVersion":1,"commands":[]}'),
      evaluatePolicy(policyInput()),
      { permissionProfile: "custom", isolation: "docker", allowWrite: false },
    );
    expect(effective.native).toEqual(["native.bash"]);
    expect(effective.workspace).toEqual([]);
    expect(effective.github).toEqual([]);
  });

  it.each(["explicit deny", "host isolation", "missing execution capability"])(
    "keeps Bash denied for %s",
    (boundary) => {
      const effective = resolveEffectiveTools(
        ["native.bash"],
        parseToolConfiguration('{"schemaVersion":1,"commands":[]}'),
        evaluatePolicy(
          policyInput({ allowExecution: boundary !== "missing execution capability" }),
        ),
        {
          permissionProfile: "custom",
          isolation: boundary === "host isolation" ? "none" : "docker",
          disallowedTools: boundary === "explicit deny" ? ["native.bash"] : [],
        },
      );
      expect(effective.native).toEqual([]);
    },
  );

  it.each([true, false])(
    "only skips scratch change inspection for an admitted disposable task: %s",
    async (allowExecution) => {
      const root = await mkdtemp(join(tmpdir(), "dsh-disposable-finalizer-"));
      roots.push(root);
      const source = join(root, "source");
      await mkdir(source);
      await writeFile(join(source, "package.json"), "{}\n");
      const workspace = await createWorkspaceSnapshot(
        { kind: "materialized-tree", root: source },
        join(root, "worker"),
      );
      await writeFile(join(workspace.workerRoot, "generated.txt"), "temporary build output");
      await symlink("generated.txt", join(workspace.workerRoot, "dependency-link"));
      const revalidateAuthority = vi.fn(() => Promise.resolve());
      const finalizer = prepareWorkspaceOperation({
        authorized: {
          client: githubClientFixture(),
          context: pullRequestContext(),
          command: {
            operation: "task",
            requestedAccess: "read",
            source: "explicit-input",
            instructions: "Inspect build",
          },
          policy: evaluatePolicy(policyInput({ allowExecution })),
          revalidateAuthority,
        },
        inputs: inputs({ allowWrite: false, taskAccess: "read" }),
        taskIdentity: "disposable-task",
        workspaceCopy: workspace,
        boundWriteSha: "a".repeat(40),
        issueNumber: 7,
        runUrl: "https://github.com/o/r/actions/runs/1",
        lifecycle: { enter: vi.fn(), update: vi.fn(() => Promise.resolve()) },
        signal: new AbortController().signal,
        deadlineMs: Date.now() + 60_000,
      });
      if (allowExecution) {
        await expect(finalizer.finalize(result, 60_000)).resolves.toEqual({
          kind: "answer",
          commentId: 7,
        });
        expect(revalidateAuthority).toHaveBeenCalledOnce();
        expect(effects.answer).toHaveBeenCalledOnce();
        expect(finalizer.snapshot()).toEqual({ commentId: 7 });
      } else {
        await expect(finalizer.finalize(result, 60_000)).rejects.toThrow();
        expect(effects.answer).not.toHaveBeenCalled();
      }
      expect(effects.write).not.toHaveBeenCalled();
    },
  );
});
