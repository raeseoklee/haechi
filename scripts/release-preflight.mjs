#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const requireNpmAuth = process.argv.includes("--require-npm-auth");
const checks = [
  ["npm", ["test"]],
  ["npm", ["run", "check:types"]],
  ["npm", ["run", "scan:stale-names"]],
  ["npm", ["run", "scan:doc-freshness"]],
  ["npm", ["run", "scan:detection"]],
  ["npm", ["run", "check:packaging"]],
  ["npm", ["run", "check:satellite-packaging"]],
  ["npm", ["pack", "--dry-run"]]
];

if (requireNpmAuth) {
  checks.push(["npm", ["whoami"]]);
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

if (requireNpmAuth) {
  const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const exactPackage = `${packageJson.name}@${packageJson.version}`;
  const exactVersion = spawnSync("npm", ["view", exactPackage, "version"], {
    encoding: "utf8",
    env: process.env
  });

  if (exactVersion.status === 0) {
    console.error(`release preflight failed: ${exactPackage} already exists on npm`);
    process.exit(1);
  }

  if (!String(exactVersion.stderr).includes("E404")) {
    process.stderr.write(exactVersion.stderr);
    console.error(`release preflight failed: npm view ${exactPackage} version`);
    process.exit(exactVersion.status ?? 1);
  }

  const packageVersion = spawnSync("npm", ["view", packageJson.name, "version"], {
    encoding: "utf8",
    env: process.env
  });

  if (packageVersion.status === 0) {
    console.error(`npm package ${packageJson.name} exists; latest published version is ${packageVersion.stdout.trim()}`);
  } else if (String(packageVersion.stderr).includes("E404")) {
    console.error(`npm package ${packageJson.name} is not published yet; first publish will claim the name`);
  } else {
    process.stderr.write(packageVersion.stderr);
    console.error(`release preflight failed: npm view ${packageJson.name} version`);
    process.exit(packageVersion.status ?? 1);
  }
}

console.error(requireNpmAuth
  ? "release preflight passed with npm auth checks"
  : "release preflight passed without npm auth checks");
