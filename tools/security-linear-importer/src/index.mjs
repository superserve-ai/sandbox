#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import process from "node:process";

const DEFAULT_TEAM_NAME = "Superserve";
const DEFAULT_PROJECT_NAME = "Security Engineering Program";
const DEFAULT_STATE_FILE = ".linear-state.json";

export function parseArgs(argv) {
  const options = { apply: false, approve: false, manifest: "security-program/issues.json" };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--apply") options.apply = true;
    else if (arg === "--yes") options.approve = true;
    else if (arg === "--manifest") options.manifest = argv[++i];
    else if (arg === "--state") options.state = argv[++i];
    else if (arg === "--help" || arg === "-h") options.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return options;
}

export function validateManifest(manifest) {
  if (!manifest || !Array.isArray(manifest.issues)) throw new Error("Manifest must contain an issues array");
  const keys = new Set();
  for (const issue of manifest.issues) {
    if (!issue.key || !issue.title) throw new Error("Every issue needs a key and title");
    if (keys.has(issue.key)) throw new Error(`Duplicate issue key: ${issue.key}`);
    keys.add(issue.key);
    if (issue.parentKey && issue.parentKey === issue.key) throw new Error(`Issue cannot parent itself: ${issue.key}`);
  }
  for (const issue of manifest.issues) {
    if (issue.parentKey && !keys.has(issue.parentKey)) throw new Error(`Unknown parent key: ${issue.parentKey}`);
  }
}

export function temporaryId(key) {
  return `dry-run:${key}`;
}

export function planSync(issues, knownIds = {}, dryRun = true) {
  const ids = new Map(Object.entries(knownIds));
  const plan = [];
  for (const issue of [...issues.filter((issue) => !issue.parentKey), ...issues.filter((issue) => issue.parentKey)]) {
    const parentId = issue.parentKey ? ids.get(issue.parentKey) : undefined;
    if (issue.parentKey && !parentId) throw new Error(`Parent ID is unavailable for ${issue.key}`);
    const knownId = ids.get(issue.key);
    const id = knownId ?? (dryRun ? temporaryId(issue.key) : undefined);
    plan.push({ action: knownId ? "update" : "create", issue, id, parentId });
    ids.set(issue.key, id ?? `pending:${issue.key}`);
  }
  return plan;
}

export class LinearClient {
  constructor(apiKey, fetchImpl = fetch) {
    this.fetch = fetchImpl;
    this.apiKey = apiKey;
  }

  async query(query, variables) {
    const response = await this.fetch("https://api.linear.app/graphql", {
      method: "POST",
      headers: { Authorization: this.apiKey, "Content-Type": "application/json" },
      body: JSON.stringify({ query, variables }),
    });
    const body = await response.json();
    if (!response.ok || body.errors?.length) throw new Error(body.errors?.map((error) => error.message).join("; ") || `Linear HTTP ${response.status}`);
    return body.data;
  }

  async resolveTeamAndProject(teamId, projectId) {
    const team = teamId ? { id: teamId } : await this.resolveTeam();
    const project = projectId ? { id: projectId } : await this.resolveProject();
    return { team, project };
  }

  async resolveTeam() {
    const data = await this.query(`query ResolveTeam($name: String!) {
      teams(filter: { name: { eq: $name } }, first: 1) { nodes { id name } }
    }`, { name: DEFAULT_TEAM_NAME });
    const team = data.teams?.nodes?.[0];
    if (!team) throw new Error(`Linear team not found: ${DEFAULT_TEAM_NAME}`);
    return team;
  }

  async resolveProject() {
    const data = await this.query(`query ResolveProject($name: String!) {
      projects(filter: { name: { eq: $name } }, first: 1) { nodes { id name } }
    }`, { name: DEFAULT_PROJECT_NAME });
    const project = data.projects?.nodes?.[0];
    if (!project) throw new Error(`Linear project not found: ${DEFAULT_PROJECT_NAME}`);
    return project;
  }

  async createIssue(input) {
    const data = await this.query(`mutation CreateIssue($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier } } }`, { input });
    if (!data.issueCreate.success) throw new Error("Linear issue creation failed");
    return data.issueCreate.issue;
  }

  async updateIssue(id, input) {
    const data = await this.query(`mutation UpdateIssue($id: String!, $input: IssueUpdateInput!) { issueUpdate(id: $id, input: $input) { success issue { id identifier } } }`, { id, input });
    if (!data.issueUpdate.success) throw new Error(`Linear issue update failed: ${id}`);
    return data.issueUpdate.issue;
  }
}

function issueInput(issue, teamId, projectId, parentId) {
  return { teamId, projectId, title: issue.title, ...(issue.description ? { description: issue.description } : {}), ...(issue.priority !== undefined ? { priority: issue.priority } : {}), ...(parentId ? { parentId } : {}) };
}

export async function sync({ issues, state, client, teamId, projectId, dryRun }) {
  validateManifest({ issues });
  const knownIds = state.issues ?? {};
  const resolved = dryRun ? { team: { id: teamId || "dry-run:team" }, project: { id: projectId || "dry-run:project" } } : await client.resolveTeamAndProject(teamId, projectId);
  const nextState = { teamId: resolved.team.id, projectId: resolved.project.id, issues: { ...knownIds } };

  const ids = new Map(Object.entries(knownIds));
  const roots = issues.filter((issue) => !issue.parentKey);
  const children = issues.filter((issue) => issue.parentKey);
  for (const issue of roots) {
    const result = await syncIssue({ issue, id: ids.get(issue.key), teamId: resolved.team.id, projectId: resolved.project.id, client, dryRun });
    ids.set(issue.key, result.id);
    nextState.issues[issue.key] = result.id;
  }
  for (const issue of children) {
    const parentId = ids.get(issue.parentKey);
    if (!parentId) throw new Error(`Parent ID is unavailable for ${issue.key}`);
    const result = await syncIssue({ issue, id: ids.get(issue.key), parentId, teamId: resolved.team.id, projectId: resolved.project.id, client, dryRun });
    ids.set(issue.key, result.id);
    nextState.issues[issue.key] = result.id;
  }
  return nextState;
}

async function syncIssue({ issue, id, parentId, teamId, projectId, client, dryRun }) {
  const action = id ? "update" : "create";
  const input = issueInput(issue, teamId, projectId, parentId);
  const result = dryRun ? { id: id || temporaryId(issue.key) } : id ? await client.updateIssue(id, input) : await client.createIssue(input);
  console.log(`${action} ${issue.key}: ${issue.title}${parentId ? ` (parent ${parentId})` : ""}`);
  return result;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log("Usage: node src/index.mjs [--manifest security-program/issues.json] [--state security-program/.linear-state.json] [--apply --yes]");
    return;
  }
  if (options.apply && (!process.env.LINEAR_API_KEY || !options.approve)) throw new Error("Apply mode requires LINEAR_API_KEY and --yes");
  const stateFile = options.state ?? `${options.manifest.split("/").slice(0, -1).join("/") || "."}/${DEFAULT_STATE_FILE}`;
  const manifest = JSON.parse(await readFile(options.manifest, "utf8"));
  let state = {};
  try { state = JSON.parse(await readFile(stateFile, "utf8")); } catch (error) { if (error.code !== "ENOENT") throw error; }
  const result = await sync({ issues: manifest.issues, state, client: new LinearClient(process.env.LINEAR_API_KEY), teamId: process.env.LINEAR_TEAM_ID || state.teamId, projectId: process.env.LINEAR_PROJECT_ID || state.projectId, dryRun: !options.apply });
  if (options.apply) await writeFile(stateFile, `${JSON.stringify(result, null, 2)}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) main().catch((error) => { console.error(`error: ${error.message}`); process.exitCode = 1; });
