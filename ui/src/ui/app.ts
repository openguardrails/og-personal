import { LitElement, html, nothing } from "lit";
import {
  TAB_GROUPS,
  type Tab,
  pathForTab,
  tabFromPath,
  titleForTab,
  subtitleForTab,
  iconForTab,
} from "./navigation.js";
import {
  createGatewayClient,
  type GatewayClient,
  type GatewayEventFrame,
} from "./gateway.js";
import { applyTheme, resolveTheme, type ThemeMode } from "./theme.js";

interface RiskAssessment {
  level: "high" | "medium" | "low" | "none";
  score: number;
  blastRadiusScore: number;
  threatScore: number;
  timestamp: number;
}

interface MoltbotState {
  configExists: boolean;
  config?: Record<string, unknown>;
  agents: Array<{
    id: string;
    sessionCount: number;
    configExists?: boolean;
    config?: Record<string, unknown>;
  }>;
  sessions: Array<{
    agentId: string;
    sessionId: string;
    path: string;
    sizeBytes?: number;
    modifiedAt?: number;
  }>;
  credentialFiles: string[];
}

// Mock data for demo-ready UI pages
interface AssetInfo {
  name: string;
  permission: "read" | "write" | "execute" | "admin";
  risk: "high" | "medium" | "low" | "none";
  impact: string;
  consequence: string;
  agents: string[];
}

interface EntryPointInfo {
  name: string;
  type: "instruction" | "content";
  active: boolean;
  triggerMode: string;
  allowFrom: string;
  riskNote: string;
}

interface TimelineEntry {
  time: string;
  type: "decision" | "tool-call" | "blocked" | "error" | "result";
  content: string;
  detail?: string;
}

interface TimelineSession {
  agent: string;
  sessionId: string;
  trigger: string;
  time: string;
  status: "completed" | "blocked" | "active";
  entries: TimelineEntry[];
}

interface ActivityItem {
  time: string;
  text: string;
  status: "ok" | "warn" | "danger";
  label: string;
}

interface SafetyRule {
  id: string;
  title: string;
  description: string;
  enabled: boolean;
  category: "confirmation" | "isolation" | "communication";
}

interface RiskHistoryPoint {
  date: string;
  score: number;
  blastRadius: number;
  threat: number;
}

export class OGApp extends LitElement {
  static properties = {
    tab: { type: String },
    theme: { type: String },
    connected: { type: Boolean },
    configured: { type: Boolean },
    moltbotInstalled: { type: Boolean },
    assessment: { type: Object },
    moltbotState: { type: Object },
    scanning: { type: Boolean },
    safetyRules: { type: Array },
  };

  declare tab: Tab;
  declare theme: ThemeMode;
  declare connected: boolean;
  declare configured: boolean;
  declare moltbotInstalled: boolean;
  declare assessment: RiskAssessment | null;
  declare moltbotState: MoltbotState | null;
  declare scanning: boolean;
  declare safetyRules: SafetyRule[];

  private client: GatewayClient | null = null;

  constructor() {
    super();
    this.tab = "overview";
    this.theme = "light";
    this.connected = false;
    this.configured = false;
    this.moltbotInstalled = false;
    this.assessment = null;
    this.moltbotState = null;
    this.scanning = false;
    this.safetyRules = this.getDefaultSafetyRules();
  }

  createRenderRoot() {
    return this;
  }

  connectedCallback() {
    super.connectedCallback();

    // Apply theme
    applyTheme(resolveTheme(this.theme));

    // Parse initial tab from URL
    const initialTab = tabFromPath(window.location.pathname);
    if (initialTab) this.tab = initialTab;

    // Listen for navigation
    window.addEventListener("popstate", () => {
      const newTab = tabFromPath(window.location.pathname);
      if (newTab) this.tab = newTab;
    });

    // Connect to gateway
    this.client = createGatewayClient(
      (msg) => this.handleMessage(msg),
      (connected) => {
        this.connected = connected;
        if (connected) {
          this.client?.getStatus();
          this.client?.getMoltbotState();
        }
      }
    );
    this.client.start();
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    this.client?.stop();
  }

  private handleMessage(msg: GatewayEventFrame) {
    switch (msg.type) {
      case "hello":
      case "status": {
        const state = msg.state as Record<string, unknown> | undefined;
        if (state) {
          this.configured = Boolean(state.configured);
          this.moltbotInstalled = Boolean(state.moltbotInstalled);
          if (state.assessment) {
            this.assessment = state.assessment as RiskAssessment;
          }
        } else {
          this.configured = Boolean(msg.configured);
          this.moltbotInstalled = Boolean(msg.moltbotInstalled);
          if (msg.assessment) {
            this.assessment = msg.assessment as RiskAssessment;
          }
        }
        break;
      }

      case "openclaw-state": {
        this.moltbotState = msg.state as MoltbotState;
        break;
      }

      case "scan-result": {
        this.scanning = false;
        this.assessment = msg.assessment as RiskAssessment;
        break;
      }

      case "agent-event": {
        const event = msg.event as { type: string; [key: string]: unknown };
        if (event.type === "scan-started") {
          this.scanning = true;
        } else if (event.type === "scan-completed") {
          this.scanning = false;
          this.assessment = event.assessment as RiskAssessment;
        }
        break;
      }
    }
  }

  private setTab(tab: Tab) {
    this.tab = tab;
    const path = pathForTab(tab);
    window.history.pushState({}, "", path);
  }

  private handleScan() {
    this.scanning = true;
    this.client?.runScan();
  }

  private toggleTheme() {
    this.theme = this.theme === "dark" ? "light" : "dark";
    applyTheme(resolveTheme(this.theme));
  }

  private toggleSafetyRule(ruleId: string) {
    this.safetyRules = this.safetyRules.map((r) =>
      r.id === ruleId ? { ...r, enabled: !r.enabled } : r
    );
  }

  // ─── Default Data ──────────────────────────────────────

  private getDefaultSafetyRules(): SafetyRule[] {
    return [
      {
        id: "confirm-delete",
        title: "Confirm before deleting files",
        description:
          "Agent must ask you before deleting, moving, or overwriting any file.",
        enabled: true,
        category: "confirmation",
      },
      {
        id: "confirm-message",
        title: "Confirm before sending messages",
        description:
          "Agent must ask before sending messages on your behalf via any channel.",
        enabled: true,
        category: "confirmation",
      },
      {
        id: "confirm-command",
        title: "Confirm before running commands",
        description:
          "Agent asks before executing system commands or scripts.",
        enabled: true,
        category: "confirmation",
      },
      {
        id: "confirm-payment",
        title: "Confirm before spending money",
        description:
          "Any payment, transfer, or purchase requires your explicit approval.",
        enabled: true,
        category: "confirmation",
      },
      {
        id: "restrict-workspace",
        title: "Restrict to workspace folder",
        description:
          "Agent can only read/write files in its designated workspace directory.",
        enabled: true,
        category: "isolation",
      },
      {
        id: "block-sensitive",
        title: "Block access to sensitive folders",
        description:
          "~/Documents, ~/Photos, ~/.ssh, and other sensitive directories are off-limits unless you approve.",
        enabled: true,
        category: "isolation",
      },
      {
        id: "mention-only",
        title: "Group chat: respond only when @mentioned",
        description:
          "In group chats, the agent only responds when explicitly mentioned, preventing accidental triggers.",
        enabled: true,
        category: "communication",
      },
      {
        id: "block-external",
        title: "Block unknown network requests",
        description:
          "Agent cannot make requests to unrecognized external URLs or APIs.",
        enabled: false,
        category: "communication",
      },
    ];
  }

  private getAssets(): Record<string, AssetInfo[]> {
    const credFiles = this.moltbotState?.credentialFiles ?? [];
    const agents = this.moltbotState?.agents ?? [];

    // Build assets from live data + known patterns
    const apps: AssetInfo[] = [];
    const files: AssetInfo[] = [];
    const tools: AssetInfo[] = [];
    const credentials: AssetInfo[] = [];
    const system: AssetInfo[] = [];

    // Infer apps from credential files
    for (const cred of credFiles) {
      const name = cred.replace(/\.(json|yml|yaml|env|key|token)$/i, "");
      const lc = name.toLowerCase();
      if (
        lc.includes("telegram") ||
        lc.includes("discord") ||
        lc.includes("slack") ||
        lc.includes("whatsapp") ||
        lc.includes("signal") ||
        lc.includes("matrix")
      ) {
        apps.push({
          name: name.charAt(0).toUpperCase() + name.slice(1),
          permission: "write",
          risk: "high",
          impact: "Sends messages as you",
          consequence: "Impersonation, fraud messages sent to contacts, damage spreads to your social network",
          agents: agents.map((a) => a.id),
        });
      } else if (
        lc.includes("gmail") ||
        lc.includes("email") ||
        lc.includes("mail")
      ) {
        apps.push({
          name: "Email",
          permission: "write",
          risk: "high",
          impact: "Reads inbox, sends emails",
          consequence: "Phishing sent from your address, confidential emails leaked, reputation damage",
          agents: agents.map((a) => a.id),
        });
      } else if (lc.includes("calendar") || lc.includes("gcal")) {
        apps.push({
          name: "Calendar",
          permission: "write",
          risk: "medium",
          impact: "Creates and modifies events",
          consequence: "Meetings cancelled or moved, schedule disruption, social engineering via fake invites",
          agents: agents.map((a) => a.id),
        });
      }
      credentials.push({
        name: cred,
        permission: "read",
        risk: "high",
        impact: "Stored authentication token",
        consequence: "Token stolen enables full account takeover, persists even after agent is stopped",
        agents: agents.map((a) => a.id),
      });
    }

    // Default tool capabilities from OpenClaw runtime
    tools.push(
      {
        name: "Browser Control",
        permission: "execute",
        risk: "high",
        impact: "Navigates web pages",
        consequence: "Reads malicious web content that hijacks agent behavior (prompt injection via web)",
        agents: agents.map((a) => a.id),
      },
      {
        name: "Shell / Terminal",
        permission: "execute",
        risk: "high",
        impact: "Runs system commands",
        consequence: "Arbitrary command execution: delete files, install malware, modify system config",
        agents: agents.map((a) => a.id),
      },
      {
        name: "File System",
        permission: "write",
        risk: "medium",
        impact: "Reads, writes, deletes files",
        consequence: "Critical files deleted or overwritten, data leak, changes may be irreversible",
        agents: agents.map((a) => a.id),
      },
      {
        name: "Code Generation",
        permission: "execute",
        risk: "medium",
        impact: "Writes and runs code",
        consequence: "Generated code may contain vulnerabilities, backdoors, or destructive logic",
        agents: agents.map((a) => a.id),
      }
    );

    // File access
    files.push(
      {
        name: "Agent Workspace",
        permission: "write",
        risk: "low",
        impact: "Designated working directory",
        consequence: "Work files corrupted or deleted, but damage contained to workspace",
        agents: agents.map((a) => a.id),
      },
      {
        name: "Session History",
        permission: "read",
        risk: "low",
        impact: "Past conversation logs",
        consequence: "Private conversations and decisions exposed if session data is exfiltrated",
        agents: agents.map((a) => a.id),
      }
    );

    // System
    system.push(
      {
        name: "Process Management",
        permission: "execute",
        risk: "medium",
        impact: "Starts/stops processes",
        consequence: "Critical services killed, persistent background processes installed",
        agents: agents.map((a) => a.id),
      },
      {
        name: "Network Access",
        permission: "execute",
        risk: "medium",
        impact: "Makes external HTTP requests",
        consequence: "Data exfiltrated to external servers, malicious payloads downloaded",
        agents: agents.map((a) => a.id),
      }
    );

    return { apps, files, tools, credentials, system };
  }

  private getEntryPoints(): EntryPointInfo[] {
    const credFiles = this.moltbotState?.credentialFiles ?? [];
    const entries: EntryPointInfo[] = [];

    for (const cred of credFiles) {
      const lc = cred.toLowerCase();
      if (lc.includes("telegram")) {
        entries.push({
          name: "Telegram",
          type: "instruction",
          active: true,
          triggerMode: "Direct message + @mention in groups",
          allowFrom: "Configured account only",
          riskNote: "Group messages may contain injection attempts",
        });
      } else if (lc.includes("discord")) {
        entries.push({
          name: "Discord",
          type: "instruction",
          active: true,
          triggerMode: "Direct message + @mention",
          allowFrom: "Configured account only",
          riskNote: "Server messages visible to all members",
        });
      } else if (lc.includes("slack")) {
        entries.push({
          name: "Slack",
          type: "instruction",
          active: true,
          triggerMode: "Direct message + @mention",
          allowFrom: "Workspace members",
          riskNote: "Channel messages may trigger unintended actions",
        });
      } else if (lc.includes("whatsapp")) {
        entries.push({
          name: "WhatsApp",
          type: "instruction",
          active: true,
          triggerMode: "Direct message only",
          allowFrom: "Configured phone number",
          riskNote: "Forwarded messages may contain manipulated content",
        });
      }
    }

    // Content entry points (always present when agent has browser/file tools)
    entries.push(
      {
        name: "Web Pages",
        type: "content",
        active: true,
        triggerMode: "Automatic when browsing",
        allowFrom: "Any URL accessed by agent",
        riskNote:
          "Web pages can contain hidden prompt injection in HTML/text",
      },
      {
        name: "Files & Documents",
        type: "content",
        active: true,
        triggerMode: "Automatic when reading files",
        allowFrom: "Any file in accessible directories",
        riskNote: "Documents may contain embedded malicious instructions",
      },
      {
        name: "Emails",
        type: "content",
        active: credFiles.some(
          (c) =>
            c.toLowerCase().includes("gmail") ||
            c.toLowerCase().includes("email")
        ),
        triggerMode: "Automatic when processing inbox",
        allowFrom: "Any sender",
        riskNote:
          "Emails are a primary vector for indirect prompt injection",
      }
    );

    return entries;
  }

  private getTimelineSessions(): TimelineSession[] {
    // Demo timeline data showing the execution replay concept
    return [
      {
        agent: "assistant-01",
        sessionId: "#2847",
        trigger: 'User message via Telegram: "Help me organize the files in Downloads"',
        time: "14:32",
        status: "completed",
        entries: [
          {
            time: "14:32:01",
            type: "decision",
            content:
              "Plan: scan ~/Downloads, categorize by file type, create folders, move files",
          },
          {
            time: "14:32:03",
            type: "tool-call",
            content: 'file_system.list("/Users/tom/Downloads")',
            detail: "47 files found",
          },
          {
            time: "14:32:05",
            type: "tool-call",
            content:
              'file_system.mkdir("/Users/tom/Downloads/Documents")',
            detail: "Directory created",
          },
          {
            time: "14:32:06",
            type: "tool-call",
            content:
              'file_system.move("report.pdf" -> "Documents/report.pdf")',
            detail: "Moved successfully",
          },
          {
            time: "14:32:07",
            type: "blocked",
            content:
              'file_system.delete("old_backup.zip") -- REQUIRES CONFIRMATION',
            detail:
              "Safety Rule: Confirm before deleting files (file > 100MB)",
          },
          {
            time: "14:33:12",
            type: "result",
            content: "User approved deletion. File deleted.",
          },
        ],
      },
      {
        agent: "assistant-01",
        sessionId: "#2846",
        trigger:
          'User message via Telegram: "Reply to the latest email from Alice"',
        time: "14:15",
        status: "blocked",
        entries: [
          {
            time: "14:15:01",
            type: "decision",
            content:
              "Plan: read latest email from Alice, draft reply, send via Gmail",
          },
          {
            time: "14:15:03",
            type: "tool-call",
            content: 'gmail.search("from:alice@example.com")',
            detail: "3 emails found, selecting most recent",
          },
          {
            time: "14:15:05",
            type: "tool-call",
            content: "gmail.read(messageId: msg_abc123)",
            detail: 'Subject: "Project Update - Q4 Numbers"',
          },
          {
            time: "14:15:07",
            type: "blocked",
            content:
              "gmail.send(reply) -- REQUIRES CONFIRMATION",
            detail:
              "Safety Rule: Confirm before sending messages. Draft shown to user.",
          },
          {
            time: "14:16:30",
            type: "result",
            content: "User rejected draft. Session ended.",
          },
        ],
      },
      {
        agent: "assistant-01",
        sessionId: "#2845",
        trigger: 'Scheduled task: "Check system health"',
        time: "13:00",
        status: "completed",
        entries: [
          {
            time: "13:00:01",
            type: "decision",
            content:
              "Plan: check disk usage, memory, running processes",
          },
          {
            time: "13:00:02",
            type: "tool-call",
            content: 'shell.exec("df -h")',
            detail: "Disk usage: 67% of 500GB",
          },
          {
            time: "13:00:03",
            type: "tool-call",
            content: 'shell.exec("free -m")',
            detail: "Memory: 12.4GB / 16GB used",
          },
          {
            time: "13:00:04",
            type: "result",
            content: "Health check completed. All metrics normal.",
          },
        ],
      },
    ];
  }

  private getRecentActivity(): ActivityItem[] {
    return [
      {
        time: "14:33",
        text: "Organized 47 files in Downloads",
        status: "ok",
        label: "Done",
      },
      {
        time: "14:16",
        text: "Email reply draft rejected by user",
        status: "warn",
        label: "Blocked",
      },
      {
        time: "14:15",
        text: "File deletion requires confirmation",
        status: "warn",
        label: "Pending",
      },
      {
        time: "13:00",
        text: "System health check completed",
        status: "ok",
        label: "Done",
      },
      {
        time: "12:30",
        text: "Prompt injection attempt detected in group chat",
        status: "danger",
        label: "Blocked",
      },
    ];
  }

  private getRiskHistory(): RiskHistoryPoint[] {
    return [
      { date: "Jan 23", score: 25, blastRadius: 30, threat: 15 },
      { date: "Jan 24", score: 32, blastRadius: 35, threat: 25 },
      { date: "Jan 25", score: 45, blastRadius: 40, threat: 55 },
      { date: "Jan 26", score: 38, blastRadius: 40, threat: 30 },
      { date: "Jan 27", score: 52, blastRadius: 45, threat: 65 },
      { date: "Jan 28", score: 35, blastRadius: 40, threat: 25 },
      { date: "Jan 29", score: this.assessment?.score ?? 20, blastRadius: this.assessment?.blastRadiusScore ?? 25, threat: this.assessment?.threatScore ?? 10 },
    ];
  }

  // ─── Render ────────────────────────────────────────────

  render() {
    return html`
      <div class="shell">
        ${this.renderTopbar()}
        ${this.renderNav()}
        <main class="content">
          ${this.renderContentHeader()}
          ${this.renderContent()}
        </main>
      </div>
    `;
  }

  private renderTopbar() {
    return html`
      <header class="topbar">
        <div class="topbar-left">
          <div class="brand">
            <img class="brand-logo" src="${this.theme === "dark" ? "./logo_rev.png" : "./logo.png"}" alt="OG Personal" />
            <div class="brand-text">
              <div class="brand-title">OG Personal</div>
              <div class="brand-sub">Security Agent</div>
            </div>
          </div>
        </div>
        <div class="topbar-status">
          <span class="badge ${this.connected ? "badge--ok" : "badge--danger"}">
            <span class="status-dot ${this.connected ? "status-dot--ok" : "status-dot--danger"}"></span>
            ${this.connected ? "Connected" : "Disconnected"}
          </span>
          <button class="btn btn--secondary btn--icon" @click=${this.toggleTheme} title="Toggle theme">
            ${this.theme === "dark" ? "☀" : "☾"}
          </button>
        </div>
      </header>
    `;
  }

  private renderNav() {
    return html`
      <nav class="nav">
        ${TAB_GROUPS.map(
          (group) => html`
            <div class="nav-group">
              <div class="nav-label">${group.label}</div>
              <div class="nav-group__items">
                ${group.tabs.map(
                  (tab) => html`
                    <button
                      class="nav-item ${this.tab === tab ? "active" : ""}"
                      @click=${() => this.setTab(tab as Tab)}
                    >
                      <span class="nav-item__icon" .innerHTML=${iconForTab(tab as Tab)}></span>
                      <span class="nav-item__text">${titleForTab(tab as Tab)}</span>
                    </button>
                  `
                )}
              </div>
            </div>
          `
        )}
      </nav>
    `;
  }

  private renderContentHeader() {
    return html`
      <div class="content-header">
        <div>
          <h1 class="page-title">${titleForTab(this.tab)}</h1>
          <p class="page-sub">${subtitleForTab(this.tab)}</p>
        </div>
        ${this.tab === "overview"
          ? html`
              <button
                class="btn btn--primary ${this.scanning ? "disabled" : ""}"
                @click=${this.handleScan}
                ?disabled=${this.scanning}
              >
                ${this.scanning ? html`<span class="spinner"></span>` : nothing}
                ${this.scanning ? "Scanning..." : "Run Scan"}
              </button>
            `
          : nothing}
      </div>
    `;
  }

  private renderContent() {
    switch (this.tab) {
      case "chat":
        return this.renderChat();
      case "overview":
        return this.renderOverview();
      case "agents":
        return this.renderAgents();
      case "assets":
        return this.renderAssets();
      case "entry-points":
        return this.renderEntryPoints();
      case "blast-radius":
        return this.renderBlastRadius();
      case "threats":
        return this.renderThreats();
      case "safety-rules":
        return this.renderSafetyRules();
      case "emergency":
        return this.renderEmergency();
      case "timeline":
        return this.renderTimeline();
      case "governance":
        return this.renderGovernance();
      case "risk-history":
        return this.renderRiskHistory();
      default:
        return html`<p>Unknown tab</p>`;
    }
  }

  // ─── Dashboard / Overview ──────────────────────────────

  private renderOverview() {
    const assessment = this.assessment;
    const level = assessment?.level ?? "none";
    const agents = this.moltbotState?.agents ?? [];
    const assets = this.getAssets();
    const totalAssets =
      assets.apps.length +
      assets.files.length +
      assets.tools.length +
      assets.credentials.length +
      assets.system.length;
    const highRiskAssets = Object.values(assets)
      .flat()
      .filter((a) => a.risk === "high").length;
    const activity = this.getRecentActivity();

    return html`
      <div class="stat-grid">
        <div class="stat-card stat-card--${level}">
          <div class="stat-card__label">Risk Level</div>
          <div class="stat-card__value">${level.toUpperCase()}</div>
          <div class="stat-card__sub">
            ${assessment ? `Score: ${assessment.score}/100` : "No scan data"}
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-card__label">Active Agents</div>
          <div class="stat-card__value">${agents.length}</div>
          <div class="stat-card__sub">
            ${this.moltbotState?.sessions.length ?? 0} sessions
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-card__label">Assets Exposed</div>
          <div class="stat-card__value">${totalAssets}</div>
          <div class="stat-card__sub">
            ${highRiskAssets} high-risk
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-card__label">Actions Today</div>
          <div class="stat-card__value">${activity.length}</div>
          <div class="stat-card__sub">
            ${activity.filter((a) => a.status !== "ok").length} blocked
          </div>
        </div>
      </div>

      <div class="grid grid-cols-2">
        ${assessment
          ? html`
              <div class="card">
                <div class="card-header">
                  <h3 class="card-title">Risk Score Breakdown</h3>
                </div>
                <div style="display: grid; gap: 16px;">
                  <div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                      <span>Exposure Level</span>
                      <span>${assessment.blastRadiusScore}/100</span>
                    </div>
                    <div class="progress">
                      <div
                        class="progress__bar progress__bar--${this.getProgressLevel(assessment.blastRadiusScore)}"
                        style="width: ${assessment.blastRadiusScore}%"
                      ></div>
                    </div>
                  </div>
                  <div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                      <span>Danger Level</span>
                      <span>${assessment.threatScore}/100</span>
                    </div>
                    <div class="progress">
                      <div
                        class="progress__bar progress__bar--${this.getProgressLevel(assessment.threatScore)}"
                        style="width: ${assessment.threatScore}%"
                      ></div>
                    </div>
                  </div>
                </div>
              </div>
            `
          : html`
              <div class="card">
                <div class="empty-state">
                  <div class="empty-state__icon" .innerHTML=${iconForTab("overview")}></div>
                  <div class="empty-state__title">No Scan Data</div>
                  <div class="empty-state__description">
                    Run a security scan to see your risk assessment.
                  </div>
                </div>
              </div>
            `}

        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Recent Activity</h3>
          </div>
          <div class="activity-feed">
            ${activity.map(
              (item) => html`
                <div class="activity-item">
                  <span class="activity-item__time">${item.time}</span>
                  <span class="activity-item__dot activity-item__dot--${item.status}"></span>
                  <span class="activity-item__text">${item.text}</span>
                  <span class="activity-item__status badge badge--${item.status === "ok" ? "ok" : item.status === "warn" ? "warn" : "danger"}">${item.label}</span>
                </div>
              `
            )}
          </div>
        </div>
      </div>
    `;
  }

  private getProgressLevel(score: number): string {
    if (score >= 70) return "high";
    if (score >= 40) return "medium";
    if (score >= 10) return "low";
    return "none";
  }

  // ─── Chat ──────────────────────────────────────────────

  private renderChat() {
    return html`
      <div class="card">
        <div class="empty-state">
          <div class="empty-state__icon" .innerHTML=${iconForTab("chat")}></div>
          <div class="empty-state__title">Chat with OG Personal</div>
          <div class="empty-state__description">
            Ask OG Personal about security concepts, your current risks, or get recommendations.
            This feature is coming soon.
          </div>
        </div>
      </div>
    `;
  }

  // ─── Agents ────────────────────────────────────────────

  private renderAgents() {
    const agents = this.moltbotState?.agents ?? [];

    if (agents.length === 0) {
      return html`
        <div class="card">
          <div class="empty-state">
            <div class="empty-state__icon" .innerHTML=${iconForTab("agents")}></div>
            <div class="empty-state__title">No Agents Found</div>
            <div class="empty-state__description">
              ${this.moltbotInstalled
                ? "No OpenClaw agents configured yet."
                : "OpenClaw is not installed."}
            </div>
          </div>
        </div>
      `;
    }

    return html`
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Agent Inventory</h3>
        </div>
        ${agents.map(
          (agent) => html`
            <div class="list-item">
              <div class="list-item__icon">
                <span .innerHTML=${iconForTab("agents")}></span>
              </div>
              <div class="list-item__content">
                <div class="list-item__title">${agent.id}</div>
                <div class="list-item__sub">${agent.sessionCount} sessions</div>
              </div>
              <span class="badge badge--ok">OK</span>
            </div>
          `
        )}
      </div>
    `;
  }

  // ─── Assets ────────────────────────────────────────────

  private renderAssets() {
    const assets = this.getAssets();

    const renderAssetCategory = (
      category: string,
      categoryDesc: string,
      iconClass: string,
      iconSvg: string,
      items: AssetInfo[]
    ) => html`
      <div class="asset-card">
        <div class="asset-card__header">
          <div class="asset-card__icon ${iconClass}">
            <span .innerHTML=${iconSvg}></span>
          </div>
          <div class="asset-card__title-group">
            <div class="asset-card__category">${category}</div>
            <div class="asset-card__count">${items.length} items</div>
          </div>
          ${items.some((i) => i.risk === "high")
            ? html`<span class="badge badge--high">${items.filter((i) => i.risk === "high").length} High Risk</span>`
            : html`<span class="badge badge--ok">OK</span>`}
        </div>
        <p style="color: var(--muted); font-size: 12px; margin: 0 0 12px 0; line-height: 1.5;">${categoryDesc}</p>
        ${items.length > 0
          ? items.map(
              (item) => html`
                <div class="asset-item-row">
                  <div class="asset-item-row__top">
                    <span class="asset-item__name">${item.name}</span>
                    <span class="asset-item__perm asset-item__perm--${item.permission}">${item.permission}</span>
                    <span class="badge badge--${item.risk}">${item.risk}</span>
                  </div>
                  <div class="asset-item-row__consequence">
                    <span class="asset-item-row__consequence-label">If compromised:</span>
                    ${item.consequence}
                  </div>
                </div>
              `
            )
          : html`<p style="color: var(--muted); font-size: 13px; padding: 8px 12px;">No items detected.</p>`}
      </div>
    `;

    return html`
      <div class="card" style="margin-bottom: 20px;">
        <div class="card-header">
          <h3 class="card-title">Your Threat Model</h3>
        </div>
        <p style="color: var(--muted); font-size: 13px; line-height: 1.6; margin: 0;">
          These are the assets your agents can access. The risk is not just "the agent has permission" —
          it's what happens when something goes wrong: a malicious web page hijacks the agent, a prompt injection
          tricks it into acting, or the agent simply makes a mistake. Below each asset you can see the
          <strong style="color: var(--text);">real-world consequences</strong> if that asset is compromised.
        </p>
      </div>

      <div class="grid grid-cols-2">
        ${renderAssetCategory(
          "Accounts & Channels",
          "Messaging apps, email, and social accounts the agent can act through. Compromise means someone impersonates you.",
          "asset-card__icon--apps",
          `<svg viewBox="0 0 24 24"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>`,
          assets.apps
        )}
        ${renderAssetCategory(
          "Tools & Executors",
          "Browser, terminal, file system, and code execution. These turn text instructions into real-world actions.",
          "asset-card__icon--tools",
          `<svg viewBox="0 0 24 24"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>`,
          assets.tools
        )}
        ${renderAssetCategory(
          "Local Files",
          "Code, documents, photos, notes, and other files the agent can access. Deletion or leak may be irreversible.",
          "asset-card__icon--files",
          `<svg viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`,
          assets.files
        )}
        ${renderAssetCategory(
          "Credentials & Tokens",
          "API keys, OAuth tokens, and session cookies. A leaked token enables full account takeover even after the agent is stopped.",
          "asset-card__icon--credentials",
          `<svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
          assets.credentials
        )}
        ${renderAssetCategory(
          "System Permissions",
          "Terminal access, process management, and network. Config changes and permission abuse are hard to detect.",
          "asset-card__icon--system",
          `<svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`,
          assets.system
        )}
      </div>
    `;
  }

  // ─── Entry Points ──────────────────────────────────────

  private renderEntryPoints() {
    const entries = this.getEntryPoints();
    const instructionEntries = entries.filter((e) => e.type === "instruction");
    const contentEntries = entries.filter((e) => e.type === "content");

    return html`
      <div class="card" style="margin-bottom: 20px;">
        <div class="card-header">
          <h3 class="card-title">Understanding Entry Points</h3>
        </div>
        <p style="color: var(--muted); font-size: 13px; line-height: 1.6;">
          Entry points are how instructions and content reach your agent. There are two types:
          <strong style="color: var(--text);">Instruction entries</strong> are direct commands from you or others (messaging channels).
          <strong style="color: var(--text);">Content entries</strong> are data the agent reads (web pages, files, emails) which could contain hidden manipulation.
          Content entries are more dangerous because they can turn text into real actions without your knowledge.
        </p>
      </div>

      <div class="grid grid-cols-2">
        <div>
          <h3 style="font-size: 13px; font-weight: 600; color: var(--text-strong); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 12px;">
            Instruction Entries
          </h3>
          <div style="display: grid; gap: 12px;">
            ${instructionEntries.length > 0
              ? instructionEntries.map(
                  (entry) => html`
                    <div class="entry-card">
                      <div class="entry-card__header">
                        <span class="entry-card__dot ${entry.active ? "entry-card__dot--active" : "entry-card__dot--inactive"}"></span>
                        <span class="entry-card__name">${entry.name}</span>
                        <span class="entry-card__type entry-card__type--instruction">Instruction</span>
                      </div>
                      <div class="entry-card__details">
                        <div class="entry-card__detail-row">
                          <span class="entry-card__detail-label">Trigger Mode</span>
                          <span class="entry-card__detail-value">${entry.triggerMode}</span>
                        </div>
                        <div class="entry-card__detail-row">
                          <span class="entry-card__detail-label">Allow From</span>
                          <span class="entry-card__detail-value">${entry.allowFrom}</span>
                        </div>
                        <div class="entry-card__detail-row">
                          <span class="entry-card__detail-label">Risk Note</span>
                          <span class="entry-card__detail-value" style="color: var(--warn);">${entry.riskNote}</span>
                        </div>
                      </div>
                    </div>
                  `
                )
              : html`
                  <div class="card">
                    <p style="color: var(--muted); font-size: 13px; text-align: center; padding: 24px;">
                      No messaging channels configured.
                    </p>
                  </div>
                `}
          </div>
        </div>

        <div>
          <h3 style="font-size: 13px; font-weight: 600; color: var(--text-strong); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 12px;">
            Content Entries
          </h3>
          <div style="display: grid; gap: 12px;">
            ${contentEntries.map(
              (entry) => html`
                <div class="entry-card">
                  <div class="entry-card__header">
                    <span class="entry-card__dot ${entry.active ? "entry-card__dot--active" : "entry-card__dot--inactive"}"></span>
                    <span class="entry-card__name">${entry.name}</span>
                    <span class="entry-card__type entry-card__type--content">Content</span>
                  </div>
                  <div class="entry-card__details">
                    <div class="entry-card__detail-row">
                      <span class="entry-card__detail-label">Trigger Mode</span>
                      <span class="entry-card__detail-value">${entry.triggerMode}</span>
                    </div>
                    <div class="entry-card__detail-row">
                      <span class="entry-card__detail-label">Source</span>
                      <span class="entry-card__detail-value">${entry.allowFrom}</span>
                    </div>
                    <div class="entry-card__detail-row">
                      <span class="entry-card__detail-label">Risk Note</span>
                      <span class="entry-card__detail-value" style="color: var(--warn);">${entry.riskNote}</span>
                    </div>
                  </div>
                </div>
              `
            )}
          </div>
        </div>
      </div>
    `;
  }

  // ─── Blast Radius ──────────────────────────────────────

  private renderBlastRadius() {
    return html`
      <div class="grid grid-cols-2">
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Connections</h3>
          </div>
          <p style="color: var(--muted); font-size: 13px;">
            Messaging channels and external services OpenClaw can access.
          </p>
          <div style="margin-top: 16px;">
            ${this.moltbotState?.credentialFiles.length
              ? this.moltbotState.credentialFiles.map(
                  (file) => html`
                    <div class="list-item">
                      <div class="list-item__content">
                        <div class="list-item__title">${file}</div>
                      </div>
                      <span class="badge badge--medium">Medium</span>
                    </div>
                  `
                )
              : html`<p style="color: var(--muted);">No credentials found.</p>`}
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h3 class="card-title">MCP Tools</h3>
          </div>
          <p style="color: var(--muted); font-size: 13px;">
            Model Context Protocol tools registered with agents.
          </p>
          <div style="margin-top: 16px;">
            <p style="color: var(--muted);">Tool inventory coming soon.</p>
          </div>
        </div>
      </div>
    `;
  }

  // ─── Threats ───────────────────────────────────────────

  private renderThreats() {
    return html`
      <div class="grid grid-cols-2">
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Protection</h3>
            <span class="badge badge--ok">Active</span>
          </div>
          <p class="card-description">Defending against attacks on the agent</p>

          <div style="margin-top: 16px;">
            ${[
              { name: "Manipulation Attack", desc: "Malicious prompts that trick the agent into harmful actions" },
              { name: "Hijack Attempt", desc: "Attempts to take over agent control by overriding system prompts" },
              { name: "Web Attacks", desc: "XSS, CSRF, SQL injection, and other web vulnerabilities" },
              { name: "Tool Tampering", desc: "Malicious modifications to MCP tool definitions" },
              { name: "Malicious Code", desc: "Dangerous code execution attempts (rm -rf, reverse shells)" },
            ].map(
              (item) => html`
                <div class="list-item">
                  <div class="list-item__content">
                    <div class="list-item__title">${item.name}</div>
                    <div class="list-item__sub">${item.desc}</div>
                  </div>
                  <span class="status-dot status-dot--ok"></span>
                </div>
              `
            )}
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Supervision</h3>
            <span class="badge badge--ok">Active</span>
          </div>
          <p class="card-description">Catching agent mistakes and data leakage</p>

          <div style="margin-top: 16px;">
            ${[
              { name: "NSFW", desc: "Not-safe-for-work content" },
              { name: "Personal Data Leak", desc: "Names, emails, SSN, credit cards, addresses" },
              { name: "Credentials", desc: "API keys, passwords, tokens" },
              { name: "Confidential", desc: "Sensitive business/personal data" },
              { name: "Off-Topic", desc: "Responses outside allowed scope" },
            ].map(
              (item) => html`
                <div class="list-item">
                  <div class="list-item__content">
                    <div class="list-item__title">${item.name}</div>
                    <div class="list-item__sub">${item.desc}</div>
                  </div>
                  <span class="status-dot status-dot--ok"></span>
                </div>
              `
            )}
          </div>
        </div>
      </div>
    `;
  }

  // ─── Safety Rules ──────────────────────────────────────

  private renderSafetyRules() {
    const categories = [
      { key: "confirmation", label: "Confirmation Gates", desc: "Require your approval before critical actions" },
      { key: "isolation", label: "Isolation & Access", desc: "Restrict what files and directories agents can access" },
      { key: "communication", label: "Communication & Network", desc: "Control how agents interact with the outside world" },
    ];

    return html`
      ${categories.map(
        (cat) => html`
          <div class="card">
            <div class="card-header">
              <div>
                <h3 class="card-title">${cat.label}</h3>
                <p class="card-description">${cat.desc}</p>
              </div>
            </div>
            ${this.safetyRules
              .filter((r) => r.category === cat.key)
              .map(
                (rule) => html`
                  <div class="rule-item">
                    <div class="rule-item__content">
                      <div class="rule-item__title">${rule.title}</div>
                      <div class="rule-item__desc">${rule.description}</div>
                    </div>
                    <label class="toggle">
                      <input
                        class="toggle__input"
                        type="checkbox"
                        ?checked=${rule.enabled}
                        @change=${() => this.toggleSafetyRule(rule.id)}
                      />
                      <span class="toggle__track"></span>
                    </label>
                  </div>
                `
              )}
          </div>
        `
      )}
    `;
  }

  // ─── Emergency Controls ────────────────────────────────

  private renderEmergency() {
    return html`
      <div class="card" style="background: var(--warn-subtle); border-color: var(--warn); margin-bottom: 20px;">
        <p style="color: var(--warn); font-size: 13px; font-weight: 500; margin: 0;">
          Emergency controls immediately affect all running agents. Use with caution. These actions are designed to limit damage when something goes wrong.
        </p>
      </div>

      <div style="display: grid; gap: 16px;">
        <div class="emergency-card">
          <div class="emergency-card__icon emergency-card__icon--pause">
            <span .innerHTML=${`<svg viewBox="0 0 24 24"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>`}></span>
          </div>
          <div class="emergency-card__body">
            <div class="emergency-card__title">Pause All Agents</div>
            <div class="emergency-card__desc">
              Immediately stop all agent activity. Running tasks will be suspended, but state is preserved.
              You can resume agents after reviewing the situation.
            </div>
            <div class="emergency-card__action">
              <button class="btn btn--secondary">Pause Agents</button>
              <span style="font-size: 12px; color: var(--muted);">Agents can be resumed later</span>
            </div>
          </div>
        </div>

        <div class="emergency-card">
          <div class="emergency-card__icon emergency-card__icon--revoke">
            <span .innerHTML=${`<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>`}></span>
          </div>
          <div class="emergency-card__body">
            <div class="emergency-card__title">Revoke All Credentials</div>
            <div class="emergency-card__desc">
              Invalidate all stored tokens, API keys, and OAuth sessions. Agents will lose access to all external services.
              You will need to re-authenticate each service after this action.
            </div>
            <div class="emergency-card__action">
              <button class="btn btn--danger">Revoke Credentials</button>
              <span style="font-size: 12px; color: var(--danger);">This action cannot be undone</span>
            </div>
          </div>
        </div>

        <div class="emergency-card">
          <div class="emergency-card__icon emergency-card__icon--rollback">
            <span .innerHTML=${`<svg viewBox="0 0 24 24"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>`}></span>
          </div>
          <div class="emergency-card__body">
            <div class="emergency-card__title">Rollback Last Session</div>
            <div class="emergency-card__desc">
              Undo all file changes made during the most recent agent session. Only works if workspace has Git or snapshot backups enabled.
              Review the execution timeline first to understand what was changed.
            </div>
            <div class="emergency-card__action">
              <button class="btn btn--secondary">Review & Rollback</button>
              <span style="font-size: 12px; color: var(--muted);">Requires Git or snapshot support</span>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  // ─── Execution Timeline ────────────────────────────────

  private renderTimeline() {
    const sessions = this.getTimelineSessions();

    return html`
      ${sessions.map(
        (session) => html`
          <div class="timeline-session">
            <div class="timeline-session__header">
              <div>
                <div class="timeline-session__agent">
                  ${session.agent}
                  <span style="color: var(--muted); font-weight: 400;"> ${session.sessionId}</span>
                </div>
                <div class="timeline-session__trigger">${session.trigger}</div>
              </div>
              <div class="timeline-session__meta">
                <div class="timeline-session__time">${session.time}</div>
                <div class="timeline-session__status">
                  <span class="badge badge--${session.status === "completed" ? "ok" : session.status === "blocked" ? "warn" : "low"}">
                    ${session.status}
                  </span>
                </div>
              </div>
            </div>
            <div class="timeline">
              ${session.entries.map(
                (entry) => html`
                  <div class="timeline-entry">
                    <div class="timeline-entry__dot timeline-entry__dot--${entry.type}"></div>
                    <div class="timeline-entry__time">${entry.time}</div>
                    <div class="timeline-entry__type timeline-entry__type--${entry.type}">
                      ${entry.type === "tool-call"
                        ? "TOOL CALL"
                        : entry.type.toUpperCase()}
                    </div>
                    <div class="timeline-entry__content">${entry.content}</div>
                    ${entry.detail
                      ? html`<div class="timeline-entry__detail">${entry.detail}</div>`
                      : nothing}
                  </div>
                `
              )}
            </div>
          </div>
        `
      )}
    `;
  }

  // ─── Governance (Audit Log) ────────────────────────────

  private renderGovernance() {
    return html`
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Security Events</h3>
        </div>
        <div class="empty-state">
          <div class="empty-state__icon" .innerHTML=${iconForTab("governance")}></div>
          <div class="empty-state__title">No Audit Events</div>
          <div class="empty-state__description">
            Security events will appear here as they are detected.
          </div>
        </div>
      </div>
    `;
  }

  // ─── Risk History ──────────────────────────────────────

  private renderRiskHistory() {
    const history = this.getRiskHistory();
    const maxScore = 100;

    return html`
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Risk Score Trend (7 Days)</h3>
        </div>
        <div class="risk-chart" style="height: 180px; padding-left: 0;">
          ${history.map(
            (point) => html`
              <div class="risk-chart__bar-group">
                <div style="flex: 1; display: flex; align-items: flex-end; gap: 2px; width: 100%;">
                  <div
                    class="risk-chart__bar"
                    style="height: ${(point.blastRadius / maxScore) * 140}px; background: var(--risk-low); opacity: 0.6; flex: 1;"
                    title="Exposure: ${point.blastRadius}"
                  ></div>
                  <div
                    class="risk-chart__bar"
                    style="height: ${(point.threat / maxScore) * 140}px; background: var(--risk-medium); opacity: 0.6; flex: 1;"
                    title="Danger: ${point.threat}"
                  ></div>
                  <div
                    class="risk-chart__bar"
                    style="height: ${(point.score / maxScore) * 140}px; background: var(--${this.getProgressLevel(point.score) === 'none' ? 'risk-none' : 'risk-' + this.getProgressLevel(point.score)}); flex: 1;"
                    title="Combined: ${point.score}"
                  ></div>
                </div>
                <div class="risk-chart__label">${point.date}</div>
              </div>
            `
          )}
        </div>
        <div style="display: flex; gap: 20px; margin-top: 16px; justify-content: center;">
          <div style="display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--muted);">
            <span style="width: 12px; height: 12px; border-radius: 2px; background: var(--risk-low); opacity: 0.6;"></span>
            Exposure
          </div>
          <div style="display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--muted);">
            <span style="width: 12px; height: 12px; border-radius: 2px; background: var(--risk-medium); opacity: 0.6;"></span>
            Danger
          </div>
          <div style="display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--muted);">
            <span style="width: 12px; height: 12px; border-radius: 2px; background: var(--accent);"></span>
            Combined
          </div>
        </div>
      </div>

      <div class="grid grid-cols-2">
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Risk Changes</h3>
          </div>
          <div style="display: grid; gap: 12px;">
            ${history.slice(-3).reverse().map(
              (point, i) => {
                const prev = i < history.length - 1 ? history[history.length - 2 - i] : null;
                const delta = prev ? point.score - prev.score : 0;
                return html`
                  <div class="list-item">
                    <div class="list-item__content">
                      <div class="list-item__title">${point.date}</div>
                      <div class="list-item__sub">Combined score: ${point.score}/100</div>
                    </div>
                    ${delta !== 0
                      ? html`<span class="badge badge--${delta > 0 ? "warn" : "ok"}">
                          ${delta > 0 ? "+" : ""}${delta}
                        </span>`
                      : html`<span class="badge badge--none">No change</span>`}
                  </div>
                `;
              }
            )}
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Period Summary</h3>
          </div>
          <div style="display: grid; gap: 12px;">
            <div style="display: flex; justify-content: space-between; font-size: 13px;">
              <span style="color: var(--muted);">Average Score</span>
              <span style="color: var(--text-strong); font-weight: 600;">
                ${Math.round(history.reduce((s, p) => s + p.score, 0) / history.length)}
              </span>
            </div>
            <div style="display: flex; justify-content: space-between; font-size: 13px;">
              <span style="color: var(--muted);">Peak Score</span>
              <span style="color: var(--text-strong); font-weight: 600;">
                ${Math.max(...history.map((p) => p.score))}
              </span>
            </div>
            <div style="display: flex; justify-content: space-between; font-size: 13px;">
              <span style="color: var(--muted);">Lowest Score</span>
              <span style="color: var(--text-strong); font-weight: 600;">
                ${Math.min(...history.map((p) => p.score))}
              </span>
            </div>
            <div style="display: flex; justify-content: space-between; font-size: 13px;">
              <span style="color: var(--muted);">Current Trend</span>
              <span style="color: var(--text-strong); font-weight: 600;">
                ${history[history.length - 1].score <= history[history.length - 2].score ? "Improving" : "Worsening"}
              </span>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  // ─── Control (legacy, kept for reference) ──────────────

  private renderControl() {
    return html`
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Detection Settings</h3>
        </div>
        <p style="color: var(--muted); margin-bottom: 16px;">
          Configure which detectors are active and their sensitivity levels.
          Settings management coming soon.
        </p>
        <button class="btn btn--secondary" disabled>Open Settings</button>
      </div>

      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Auto-Remediation</h3>
          <span class="badge badge--medium">Disabled</span>
        </div>
        <p style="color: var(--muted);">
          Automatically block or remediate high-risk threats when detected.
        </p>
      </div>
    `;
  }
}

// Register the custom element
customElements.define("og-app", OGApp);
