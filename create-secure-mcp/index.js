#!/usr/bin/env node
// create-secure-mcp: copies the template into a new folder and names it.
// No dependencies, so `npx create-secure-mcp` starts instantly.
import { cpSync, existsSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const arg = process.argv[2];

if (!arg || arg === "-h" || arg === "--help") {
  console.log("Usage: npx create-secure-mcp <folder>\n\nCreates an MCP server with Secure AI built in.");
  process.exit(arg ? 0 : 1);
}

const target = resolve(process.cwd(), arg);
if (existsSync(target) && readdirSync(target).length > 0) {
  console.error(`${arg} already exists and is not empty. Pick another name.`);
  process.exit(1);
}

const name = basename(target).toLowerCase().replace(/[^a-z0-9-_.]/g, "-");
cpSync(join(here, "template"), target, { recursive: true });

// npm drops a published .gitignore, so it travels as "gitignore".
if (existsSync(join(target, "gitignore"))) renameSync(join(target, "gitignore"), join(target, ".gitignore"));

for (const file of ["package.json", "README.md", join("src", "index.ts")]) {
  const path = join(target, file);
  writeFileSync(path, readFileSync(path, "utf8").replaceAll("__NAME__", name));
}

console.log(`
Created ${name}.

  cd ${arg}
  npm install
  cp .env.example .env    # then paste your key from secureai.one -> Settings -> Developer
  npm run build

Add it to Claude Desktop, Cursor or any MCP client as:
  node ${join(arg, "dist", "index.js").replaceAll("\\", "/")}
`);
