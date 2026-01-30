import { loadConfig, saveConfig, type OGConfig } from "../config/io.js";
import {
  OpenClawWatcher,
  type OpenClawState,
  type WatchEvent,
} from "./openclaw-watcher.js";
import {
  OGLLMClient,
  type DetectionResult,
  type DetectionType,
} from "./og-llm-client.js";

export type RiskLevel = "high" | "medium" | "low" | "none";

export interface RiskAssessment {
  level: RiskLevel;
  score: number; // 0-100
  blastRadiusScore: number;
  threatScore: number;
  detections: DetectionResult[];
  timestamp: number;
}

export interface BlastRadiusReport {
  connections: ConnectionInfo[];
  mcpTools: MCPToolInfo[];
  skills: SkillInfo[];
  fileAccess: FileAccessInfo[];
  totalScore: number;
}

export interface ConnectionInfo {
  type: string;
  name: string;
  riskLevel: RiskLevel;
  details?: Record<string, unknown>;
}

export interface MCPToolInfo {
  name: string;
  description: string;
  riskLevel: RiskLevel;
}

export interface SkillInfo {
  name: string;
  enabled: boolean;
  riskLevel: RiskLevel;
}

export interface FileAccessInfo {
  path: string;
  type: "read" | "write" | "execute";
  riskLevel: RiskLevel;
}

export type OGAgentEvent =
  | { type: "started" }
  | { type: "stopped" }
  | { type: "scan-started" }
  | { type: "scan-completed"; assessment: RiskAssessment }
  | { type: "risk-detected"; detection: DetectionResult }
  | { type: "openclaw-changed"; event: WatchEvent }
  | { type: "error"; error: Error };

export type OGAgentEventHandler = (event: OGAgentEvent) => void;

/**
 * OG Personal Security Agent - Main security monitoring agent for OpenClaw
 */
export class OGAgent {
  private config: OGConfig;
  private watcher: OpenClawWatcher;
  private llmClient: OGLLMClient | null = null;
  private isRunning = false;
  private scanInterval: ReturnType<typeof setInterval> | null = null;
  private handlers: OGAgentEventHandler[] = [];
  private lastAssessment: RiskAssessment | null = null;

  constructor() {
    this.config = loadConfig();
    this.watcher = new OpenClawWatcher();

    // Initialize LLM client if API key is configured
    if (this.config.apiKey) {
      this.llmClient = new OGLLMClient({
        apiKey: this.config.apiKey,
        apiBaseUrl: this.config.apiBaseUrl,
        model: this.config.model,
      });
    }

    // Set up watcher event handler
    this.watcher.onEvent((event) => this.handleWatchEvent(event));
  }

  /**
   * Add an event handler
   */
  onEvent(handler: OGAgentEventHandler): void {
    this.handlers.push(handler);
  }

  /**
   * Remove an event handler
   */
  offEvent(handler: OGAgentEventHandler): void {
    const idx = this.handlers.indexOf(handler);
    if (idx >= 0) {
      this.handlers.splice(idx, 1);
    }
  }

  /**
   * Get current configuration
   */
  getConfig(): OGConfig {
    return this.config;
  }

  /**
   * Update configuration
   */
  updateConfig(updates: Partial<OGConfig>): void {
    this.config = { ...this.config, ...updates };
    saveConfig(this.config);

    // Reinitialize LLM client if API key changed
    if (updates.apiKey !== undefined) {
      if (this.config.apiKey) {
        this.llmClient = new OGLLMClient({
          apiKey: this.config.apiKey,
          apiBaseUrl: this.config.apiBaseUrl,
          model: this.config.model,
        });
      } else {
        this.llmClient = null;
      }
    }
  }

  /**
   * Check if agent is configured and ready
   */
  isConfigured(): boolean {
    return Boolean(this.config.apiKey);
  }

  /**
   * Check if OpenClaw is installed
   */
  isOpenClawInstalled(): boolean {
    return OpenClawWatcher.isOpenClawInstalled();
  }

  /**
   * Get current OpenClaw state
   */
  getOpenClawState(): OpenClawState {
    return OpenClawWatcher.getState();
  }

  /** @deprecated Use isOpenClawInstalled */
  isMoltbotInstalled(): boolean {
    return this.isOpenClawInstalled();
  }

  /** @deprecated Use getOpenClawState */
  getMoltbotState(): OpenClawState {
    return this.getOpenClawState();
  }

  /**
   * Get last risk assessment
   */
  getLastAssessment(): RiskAssessment | null {
    return this.lastAssessment;
  }

  /**
   * Start the security agent
   */
  start(): void {
    if (this.isRunning) return;
    this.isRunning = true;

    this.emit({ type: "started" });

    // Start file watcher
    if (this.config.scan.watchFiles) {
      this.watcher.start();
    }

    // Start periodic scanning
    if (this.config.scan.intervalMs > 0) {
      this.scanInterval = setInterval(
        () => void this.runScan(),
        this.config.scan.intervalMs
      );
    }

    // Run initial scan
    void this.runScan();
  }

  /**
   * Stop the security agent
   */
  async stop(): Promise<void> {
    if (!this.isRunning) return;
    this.isRunning = false;

    if (this.scanInterval) {
      clearInterval(this.scanInterval);
      this.scanInterval = null;
    }

    await this.watcher.stop();
    this.emit({ type: "stopped" });
  }

  /**
   * Run a security scan
   */
  async runScan(): Promise<RiskAssessment> {
    this.emit({ type: "scan-started" });

    const detections: DetectionResult[] = [];
    const state = this.getOpenClawState();

    // Scan config for security issues
    if (this.llmClient && state.config) {
      const configDetection = await this.llmClient.detect({
        type: "config-audit",
        content: JSON.stringify(state.config, null, 2),
      });
      detections.push(configDetection);

      if (configDetection.isRisk) {
        this.emit({ type: "risk-detected", detection: configDetection });
      }
    }

    // Calculate blast radius
    const blastRadius = this.calculateBlastRadius(state);

    // Calculate overall risk
    const assessment = this.calculateRiskAssessment(detections, blastRadius);
    this.lastAssessment = assessment;

    // Update last scan time
    this.config.lastScanAt = new Date().toISOString();
    saveConfig(this.config);

    this.emit({ type: "scan-completed", assessment });
    return assessment;
  }

  /**
   * Analyze content for threats
   */
  async analyzeContent(
    content: string,
    types?: DetectionType[]
  ): Promise<DetectionResult[]> {
    if (!this.llmClient) {
      throw new Error("LLM client not configured");
    }

    const detectionTypes: DetectionType[] = types ?? [
      "prompt-injection",
      "pii",
      "credentials",
    ];

    const results = await this.llmClient.detectBatch(
      detectionTypes.map((type) => ({ type, content }))
    );

    for (const result of results) {
      if (result.isRisk) {
        this.emit({ type: "risk-detected", detection: result });
      }
    }

    return results;
  }

  /**
   * Quick local check for obvious risks
   */
  quickCheck(content: string): { hasRisk: boolean; patterns: string[] } {
    if (!this.llmClient) {
      return { hasRisk: false, patterns: [] };
    }
    const result = this.llmClient.quickCheck(content);
    return { hasRisk: result.hasObviousRisk, patterns: result.patterns };
  }

  /**
   * Calculate blast radius from OpenClaw state
   */
  private calculateBlastRadius(state: OpenClawState): BlastRadiusReport {
    const report: BlastRadiusReport = {
      connections: [],
      mcpTools: [],
      skills: [],
      fileAccess: [],
      totalScore: 0,
    };

    if (!state.config) return report;

    // Check for configured channels/connections
    const channelTypes = [
      "telegram",
      "discord",
      "slack",
      "whatsapp",
      "signal",
      "imessage",
    ];
    for (const channel of channelTypes) {
      const channelConfig = (state.config as Record<string, unknown>)[channel];
      if (channelConfig && typeof channelConfig === "object") {
        const config = channelConfig as Record<string, unknown>;
        if (config.enabled !== false) {
          report.connections.push({
            type: "messaging",
            name: channel,
            riskLevel: "medium",
            details: { hasToken: Boolean(config.token || config.apiKey) },
          });
        }
      }
    }

    // Check for MCP tools
    const tools = (state.config as Record<string, unknown>).tools;
    if (tools && typeof tools === "object") {
      const toolsConfig = tools as Record<string, unknown>;
      if (toolsConfig.mcp && Array.isArray(toolsConfig.mcp)) {
        for (const mcp of toolsConfig.mcp as Record<string, unknown>[]) {
          report.mcpTools.push({
            name: String(mcp.name ?? "unknown"),
            description: String(mcp.description ?? ""),
            riskLevel: "medium",
          });
        }
      }
    }

    // Calculate total score (0-100)
    report.totalScore = Math.min(
      100,
      report.connections.length * 15 +
        report.mcpTools.length * 10 +
        report.skills.length * 5 +
        report.fileAccess.length * 20
    );

    return report;
  }

  /**
   * Calculate overall risk assessment
   */
  private calculateRiskAssessment(
    detections: DetectionResult[],
    blastRadius: BlastRadiusReport
  ): RiskAssessment {
    // Calculate threat score from detections
    let threatScore = 0;
    for (const detection of detections) {
      if (detection.isRisk) {
        switch (detection.riskLevel) {
          case "high":
            threatScore += 40;
            break;
          case "medium":
            threatScore += 20;
            break;
          case "low":
            threatScore += 10;
            break;
        }
      }
    }
    threatScore = Math.min(100, threatScore);

    // Combine scores
    const combinedScore = Math.round(
      threatScore * 0.6 + blastRadius.totalScore * 0.4
    );

    // Determine overall risk level
    let level: RiskLevel = "none";
    if (combinedScore >= 70) level = "high";
    else if (combinedScore >= 40) level = "medium";
    else if (combinedScore >= 10) level = "low";

    return {
      level,
      score: combinedScore,
      blastRadiusScore: blastRadius.totalScore,
      threatScore,
      detections,
      timestamp: Date.now(),
    };
  }

  /**
   * Handle file watcher events
   */
  private handleWatchEvent(event: WatchEvent): void {
    this.emit({ type: "openclaw-changed", event });

    // Trigger a rescan on significant changes
    if (event.type === "config-changed" || event.type === "credentials-changed") {
      void this.runScan();
    }
  }

  /**
   * Emit an event to all handlers
   */
  private emit(event: OGAgentEvent): void {
    for (const handler of this.handlers) {
      try {
        handler(event);
      } catch (err) {
        console.error("[OG] Event handler error:", err);
      }
    }
  }
}
