import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { watch, type FSWatcher } from "chokidar";
import { OPENCLAW_PATHS, getOpenClawConfigPath } from "../config/paths.js";

export type WatchEvent = {
  type: "config-changed" | "agent-changed" | "session-changed" | "credentials-changed";
  path: string;
  timestamp: number;
  details?: Record<string, unknown>;
};

export type WatchEventHandler = (event: WatchEvent) => void;

export interface OpenClawState {
  configExists: boolean;
  config: Record<string, unknown> | null;
  agents: AgentInfo[];
  sessions: SessionInfo[];
  credentialFiles: string[];
}

export interface AgentInfo {
  id: string;
  path: string;
  configExists: boolean;
  config?: Record<string, unknown>;
  sessionCount: number;
}

export interface SessionInfo {
  agentId: string;
  sessionId: string;
  path: string;
  sizeBytes: number;
  modifiedAt: number;
}

/**
 * Watches OpenClaw configuration and state for changes
 */
export class OpenClawWatcher {
  private watcher: FSWatcher | null = null;
  private handlers: WatchEventHandler[] = [];
  private isRunning = false;

  /**
   * Check if OpenClaw is installed
   */
  static isOpenClawInstalled(): boolean {
    return existsSync(OPENCLAW_PATHS.base);
  }

  /**
   * Get current OpenClaw state snapshot
   */
  static getState(): OpenClawState {
    const configPath = getOpenClawConfigPath();
    const state: OpenClawState = {
      configExists: existsSync(configPath),
      config: null,
      agents: [],
      sessions: [],
      credentialFiles: [],
    };

    // Load main config
    if (state.configExists) {
      try {
        const raw = readFileSync(configPath, "utf-8");
        state.config = JSON.parse(raw);
      } catch {
        // Config exists but couldn't be parsed
      }
    }

    // Scan agents
    if (existsSync(OPENCLAW_PATHS.agents)) {
      try {
        const agentDirs = readdirSync(OPENCLAW_PATHS.agents, { withFileTypes: true });
        for (const dir of agentDirs) {
          if (!dir.isDirectory()) continue;

          const agentPath = join(OPENCLAW_PATHS.agents, dir.name);
          const agentConfigPath = join(agentPath, "agent.json");
          const sessionsPath = join(agentPath, "sessions");

          const agent: AgentInfo = {
            id: dir.name,
            path: agentPath,
            configExists: existsSync(agentConfigPath),
            sessionCount: 0,
          };

          if (agent.configExists) {
            try {
              const raw = readFileSync(agentConfigPath, "utf-8");
              agent.config = JSON.parse(raw);
            } catch {
              // Ignore parse errors
            }
          }

          // Count sessions
          if (existsSync(sessionsPath)) {
            try {
              const sessionFiles = readdirSync(sessionsPath).filter((f) =>
                f.endsWith(".jsonl")
              );
              agent.sessionCount = sessionFiles.length;

              // Add session info
              for (const sessionFile of sessionFiles) {
                const sessionPath = join(sessionsPath, sessionFile);
                const stats = statSync(sessionPath);
                state.sessions.push({
                  agentId: dir.name,
                  sessionId: sessionFile.replace(".jsonl", ""),
                  path: sessionPath,
                  sizeBytes: stats.size,
                  modifiedAt: stats.mtimeMs,
                });
              }
            } catch {
              // Ignore errors
            }
          }

          state.agents.push(agent);
        }
      } catch {
        // Ignore errors scanning agents
      }
    }

    // Scan credentials
    if (existsSync(OPENCLAW_PATHS.credentials)) {
      try {
        const credFiles = readdirSync(OPENCLAW_PATHS.credentials);
        state.credentialFiles = credFiles;
      } catch {
        // Ignore errors
      }
    }

    return state;
  }

  /**
   * Add an event handler
   */
  onEvent(handler: WatchEventHandler): void {
    this.handlers.push(handler);
  }

  /**
   * Remove an event handler
   */
  offEvent(handler: WatchEventHandler): void {
    const idx = this.handlers.indexOf(handler);
    if (idx >= 0) {
      this.handlers.splice(idx, 1);
    }
  }

  /**
   * Start watching for changes
   */
  start(): void {
    if (this.isRunning) return;
    if (!OpenClawWatcher.isOpenClawInstalled()) {
      console.warn("[OG] OpenClaw is not installed, skipping file watching");
      return;
    }

    this.isRunning = true;

    // Watch all relevant paths
    const configPath = getOpenClawConfigPath();
    const pathsToWatch = [
      configPath,
      OPENCLAW_PATHS.agents,
      OPENCLAW_PATHS.credentials,
    ].filter((p) => existsSync(p) || existsSync(join(p, "..")));

    this.watcher = watch(pathsToWatch, {
      persistent: true,
      ignoreInitial: true,
      awaitWriteFinish: {
        stabilityThreshold: 500,
        pollInterval: 100,
      },
    });

    this.watcher.on("change", (path) => this.handleFileChange(path, "change"));
    this.watcher.on("add", (path) => this.handleFileChange(path, "add"));
    this.watcher.on("unlink", (path) => this.handleFileChange(path, "unlink"));
  }

  /**
   * Stop watching
   */
  async stop(): Promise<void> {
    if (!this.isRunning) return;
    this.isRunning = false;

    if (this.watcher) {
      await this.watcher.close();
      this.watcher = null;
    }
  }

  /**
   * Handle a file change event
   */
  private handleFileChange(path: string, changeType: string): void {
    const timestamp = Date.now();
    let event: WatchEvent | null = null;

    if (path.endsWith("openclaw.json") || path.endsWith("clawdbot.json") || path.endsWith("openclaw.json")) {
      event = {
        type: "config-changed",
        path,
        timestamp,
        details: { changeType },
      };
    } else if (path.includes("/agents/")) {
      event = {
        type: "agent-changed",
        path,
        timestamp,
        details: { changeType },
      };
    } else if (path.includes("/sessions/")) {
      event = {
        type: "session-changed",
        path,
        timestamp,
        details: { changeType },
      };
    } else if (path.includes("/credentials/")) {
      event = {
        type: "credentials-changed",
        path,
        timestamp,
        details: { changeType },
      };
    }

    if (event) {
      this.emit(event);
    }
  }

  /**
   * Emit an event to all handlers
   */
  private emit(event: WatchEvent): void {
    for (const handler of this.handlers) {
      try {
        handler(event);
      } catch (err) {
        console.error("[OG] Event handler error:", err);
      }
    }
  }
}

// Legacy aliases
/** @deprecated Use OpenClawWatcher instead */
export const MoltbotWatcher = OpenClawWatcher;
/** @deprecated Use OpenClawState instead */
export type MoltbotState = OpenClawState;
