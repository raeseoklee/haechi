#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";

const result = spawnSync("npm", ["sbom", "--sbom-format", "cyclonedx"], {
  encoding: "utf8"
});

if (result.status !== 0) {
  process.stderr.write(result.stderr);
  process.exit(result.status ?? 1);
}

const packageJson = JSON.parse(await readFile("package.json", "utf8"));
const sbom = JSON.parse(result.stdout);

if (sbom.metadata?.component) {
  sbom.metadata.component.name = packageJson.name;
  sbom.metadata.component.version = packageJson.version;
  sbom.metadata.component["bom-ref"] = `${packageJson.name}@${packageJson.version}`;
}

await writeFile("sbom.cdx.json", `${JSON.stringify(sbom, null, 2)}\n`, "utf8");
process.stderr.write(`wrote sbom.cdx.json for ${packageJson.name}@${packageJson.version}\n`);
