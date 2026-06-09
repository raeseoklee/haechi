#!/usr/bin/env node
import { spawnSync } from "node:child_process";

const requireNpmAuth = process.argv.includes("--require-npm-auth");
const checks = [
  ["npm", ["test"]],
  ["npm", ["run", "scan:stale-names"]],
  ["npm", ["pack", "--dry-run"]]
];

if (requireNpmAuth) {
  checks.push(["npm", ["whoami"]]);
  checks.push(["npm", ["view", "haechi", "version"]]);
}

for (const [command, args] of checks) {
  const label = `${command} ${args.join(" ")}`;
  console.error(`> ${label}`);
  const result = spawnSync(command, args, {
    stdio: "inherit",
    env: process.env
  });

  if (result.status !== 0) {
    console.error(`release preflight failed: ${label}`);
    process.exit(result.status ?? 1);
  }
}

console.error(requireNpmAuth
  ? "release preflight passed with npm auth checks"
  : "release preflight passed without npm auth checks");
