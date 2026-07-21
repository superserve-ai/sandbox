import test from "node:test";
import assert from "node:assert/strict";
import { planSync, sync } from "../src/index.mjs";

const issues = [
  { key: "program", title: "Security program" },
  { key: "access", title: "Access review", parentKey: "program" },
  { key: "logging", title: "Logging review", parentKey: "program" },
];

test("dry-run assigns deterministic IDs and resolves child parents", async () => {
  const plan = planSync(issues, {}, true);
  assert.deepEqual(plan.map(({ action, id, parentId }) => ({ action, id, parentId })), [
    { action: "create", id: "dry-run:program", parentId: undefined },
    { action: "create", id: "dry-run:access", parentId: "dry-run:program" },
    { action: "create", id: "dry-run:logging", parentId: "dry-run:program" },
  ]);
});

test("sync updates cached IDs in root-before-child order", async () => {
  const calls = [];
  const client = {
    resolveTeamAndProject: async () => ({ team: { id: "team" }, project: { id: "project" } }),
    updateIssue: async (id, input) => { calls.push(["update", id, input.parentId]); return { id }; },
    createIssue: async (input) => { calls.push(["create", input.title, input.parentId]); return { id: `new:${input.title}` }; },
  };
  const state = await sync({ issues, state: { issues: { program: "existing-program" } }, client, dryRun: false });
  assert.deepEqual(calls, [["update", "existing-program", undefined], ["create", "Access review", "existing-program"], ["create", "Logging review", "existing-program"]]);
  assert.equal(state.issues.access, "new:Access review");
});

test("fresh apply creates children with the real root ID", async () => {
  const calls = [];
  const client = {
    resolveTeamAndProject: async () => ({ team: { id: "team" }, project: { id: "project" } }),
    createIssue: async (input) => {
      calls.push(input);
      return { id: input.parentId ? "child-id" : "root-id" };
    },
    updateIssue: async () => { throw new Error("unexpected update"); },
  };
  await sync({ issues, state: {}, client, dryRun: false });
  assert.deepEqual(calls.map(({ title, parentId }) => ({ title, parentId })), [
    { title: "Security program", parentId: undefined },
    { title: "Access review", parentId: "root-id" },
    { title: "Logging review", parentId: "root-id" },
  ]);
});

test("ID overrides avoid all resolver queries", async () => {
  let resolverCalled = false;
  const client = {
    resolveTeamAndProject: async () => { resolverCalled = true; throw new Error("resolver should not run"); },
    updateIssue: async (id) => ({ id }),
  };
  const state = await sync({
    issues: [{ key: "program", title: "Security program" }],
    state: { issues: { program: "issue" } },
    client,
    teamId: "team",
    projectId: "project",
    dryRun: false,
  });
  assert.equal(resolverCalled, false);
  assert.equal(state.teamId, "team");
  assert.equal(state.projectId, "project");
});

test("persists each successful mutation before a later failure", async () => {
  const persisted = [];
  const client = {
    resolveTeamAndProject: async () => ({ team: { id: "team" }, project: { id: "project" } }),
    createIssue: async (input) => {
      if (input.title === "Logging review") throw new Error("temporary Linear failure");
      return { id: input.parentId ? `child:${input.title}` : "root-id" };
    },
  };
  await assert.rejects(() => sync({
    issues,
    state: {},
    client,
    dryRun: false,
    persistState: async (state) => persisted.push(structuredClone(state)),
  }), /temporary Linear failure/);
  assert.deepEqual(persisted.at(-1), {
    teamId: "team",
    projectId: "project",
    issues: { program: "root-id", access: "child:Access review" },
  });
});
