import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { OG_PATHS } from "./paths.js";
import { DEFAULT_CONFIG, OGConfigSchema, type OGConfig } from "./schema.js";

/**
 * Load OG Personal configuration from disk
 * Returns default config if file doesn't exist
 */
export function loadConfig(): OGConfig {
  if (!existsSync(OG_PATHS.config)) {
    return DEFAULT_CONFIG;
  }

  try {
    const raw = readFileSync(OG_PATHS.config, "utf-8");
    const parsed = JSON.parse(raw);
    return OGConfigSchema.parse(parsed);
  } catch (err) {
    console.error(`[OG] Failed to load config: ${err}`);
    return DEFAULT_CONFIG;
  }
}

/**
 * Save OG Personal configuration to disk
 */
export function saveConfig(config: OGConfig): void {
  const dir = dirname(OG_PATHS.config);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  const validated = OGConfigSchema.parse(config);
  writeFileSync(OG_PATHS.config, JSON.stringify(validated, null, 2) + "\n");
}

/**
 * Update specific fields in the config
 */
export function updateConfig(updates: Partial<OGConfig>): OGConfig {
  const current = loadConfig();
  const merged = { ...current, ...updates };
  saveConfig(merged);
  return merged;
}

/**
 * Check if OG Personal has been configured (API key set)
 */
export function isConfigured(): boolean {
  const config = loadConfig();
  return Boolean(config.apiKey);
}

/**
 * Check if onboarding is complete
 */
export function isOnboarded(): boolean {
  const config = loadConfig();
  return config.onboardingComplete;
}

export { type OGConfig };
