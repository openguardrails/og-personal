#!/usr/bin/env node
// OG Personal - CLI entry point
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { existsSync } from "node:fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Check if built output exists
const distPath = resolve(__dirname, "dist/cli/program.js");
if (existsSync(distPath)) {
  // Production: run compiled JavaScript
  await import(distPath);
} else {
  // Development: use tsx via node --import
  // This requires running with: node --import tsx/esm og.mjs
  console.error("Error: Built output not found. Run 'npm run build' first.");
  console.error("For development, use: npx tsx src/cli/program.ts");
  process.exit(1);
}
