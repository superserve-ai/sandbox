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
