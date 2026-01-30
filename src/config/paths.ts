import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * OG Personal configuration paths
 * Uses ~/.og-personal/ for config and state
 */
export const OG_PATHS = {
  /** Base config directory */
  base: join(homedir(), ".og-personal"),

  /** Main config file */
  config: join(homedir(), ".og-personal", "config.json"),

  /** Audit log file */
  auditLog: join(homedir(), ".og-personal", "audit.jsonl"),

  /** Risk history database */
  riskHistory: join(homedir(), ".og-personal", "risk-history.db"),

  /** Cache directory */
  cache: join(homedir(), ".og-personal", "cache"),

  /** Temporary scan results */
  scanResults: join(homedir(), ".og-personal", "scans"),
} as const;

/** New canonical OpenClaw state directory */
const OPENCLAW_BASE = join(homedir(), ".openclaw");

/** Legacy state directories for backward compatibility */
const LEGACY_BASES = [
  join(homedir(), ".clawdbot"),
  join(homedir(), ".openclaw"),
] as const;

/**
 * Resolve the OpenClaw state base directory.
 * Prefers ~/.openclaw, falls back to legacy dirs if they exist.
 */
function resolveOpenClawBase(): string {
  if (existsSync(OPENCLAW_BASE)) return OPENCLAW_BASE;
  for (const legacy of LEGACY_BASES) {
    if (existsSync(legacy)) return legacy;
  }
  return OPENCLAW_BASE; // Default for new installs
}

/**
 * Resolve the OpenClaw config file path.
 * Checks openclaw.json first, then legacy names.
 */
export function getOpenClawConfigPath(): string {
  const base = resolveOpenClawBase();
  const candidates = [
    join(base, "openclaw.json"),
    join(base, "clawdbot.json"),
    join(base, "openclaw.json"),
  ];

  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  return join(base, "openclaw.json"); // Default for new installs
}

/**
 * OpenClaw paths that OG Personal monitors (read-only)
 */
export const OPENCLAW_PATHS = {
  /** OpenClaw config directory */
  get base() {
    return resolveOpenClawBase();
  },

  /** OpenClaw credentials directory */
  get credentials() {
    return join(resolveOpenClawBase(), "credentials");
  },

  /** OpenClaw agents directory */
  get agents() {
    return join(resolveOpenClawBase(), "agents");
  },

  /** OpenClaw sessions directory */
  get sessions() {
    return join(resolveOpenClawBase(), "sessions");
  },
} as const;

// Legacy aliases for backward compatibility
/** @deprecated Use OPENCLAW_PATHS instead */
export const MOLTBOT_PATHS = OPENCLAW_PATHS;
/** @deprecated Use getOpenClawConfigPath instead */
export const getMoltbotConfigPath = getOpenClawConfigPath;
