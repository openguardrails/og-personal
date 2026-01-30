export const TAB_GROUPS = [
  { label: "Chat", tabs: ["chat"] },
  {
    label: "Observability",
    tabs: ["overview", "agents", "assets", "entry-points", "blast-radius"],
  },
  { label: "Protect", tabs: ["threats", "safety-rules", "emergency"] },
  {
    label: "Govern",
    tabs: ["timeline", "governance", "risk-history"],
  },
] as const;

export type Tab =
  | "chat"
  | "overview"
  | "agents"
  | "assets"
  | "entry-points"
  | "blast-radius"
  | "threats"
  | "safety-rules"
  | "emergency"
  | "timeline"
  | "governance"
  | "risk-history";

const TAB_PATHS: Record<Tab, string> = {
  chat: "/chat",
  overview: "/overview",
  agents: "/agents",
  assets: "/assets",
  "entry-points": "/entry-points",
  "blast-radius": "/blast-radius",
  threats: "/threats",
  "safety-rules": "/safety-rules",
  emergency: "/emergency",
  timeline: "/timeline",
  governance: "/governance",
  "risk-history": "/risk-history",
};

const PATH_TO_TAB = new Map(
  Object.entries(TAB_PATHS).map(([tab, path]) => [path, tab as Tab])
);

export function pathForTab(tab: Tab): string {
  return TAB_PATHS[tab];
}

export function tabFromPath(pathname: string): Tab | null {
  let normalized = pathname || "/";
  if (normalized === "/") return "overview";
  return PATH_TO_TAB.get(normalized) ?? null;
}

export function titleForTab(tab: Tab): string {
  switch (tab) {
    case "chat":
      return "Chat with OG Personal";
    case "overview":
      return "Dashboard";
    case "agents":
      return "Agents";
    case "assets":
      return "Assets";
    case "entry-points":
      return "Entry Points";
    case "blast-radius":
      return "Blast Radius";
    case "threats":
      return "Threat Detection";
    case "safety-rules":
      return "Safety Rules";
    case "emergency":
      return "Emergency Controls";
    case "timeline":
      return "Execution Timeline";
    case "governance":
      return "Audit Log";
    case "risk-history":
      return "Risk History";
    default:
      return "Dashboard";
  }
}

export function subtitleForTab(tab: Tab): string {
  switch (tab) {
    case "chat":
      return "Ask OG Personal about security, risks, and recommendations.";
    case "overview":
      return "Overall health, risk score, and recent activity at a glance.";
    case "agents":
      return "View all OpenClaw agents and their security posture.";
    case "assets":
      return "Apps, files, tools, and credentials your agents can access.";
    case "entry-points":
      return "Channels, triggers, and who can activate your agents.";
    case "blast-radius":
      return "Visualize what OpenClaw can access and damage scope.";
    case "threats":
      return "Protection and supervision threat detectors.";
    case "safety-rules":
      return "Plain-language safety policies to protect your agent.";
    case "emergency":
      return "Pause agents, revoke credentials, and rollback actions.";
    case "timeline":
      return "Step-by-step replay of every agent decision and action.";
    case "governance":
      return "Security events, alerts, and compliance records.";
    case "risk-history":
      return "Risk trend over time and before/after comparisons.";
    default:
      return "";
  }
}

// SVG icons for tabs
export function iconForTab(tab: Tab): string {
  switch (tab) {
    case "chat":
      return `<svg viewBox="0 0 24 24"><path d="m3 21 1.9-5.7a8.5 8.5 0 1 1 3.8 3.8z"/></svg>`;
    case "overview":
      return `<svg viewBox="0 0 24 24"><path d="M3 3v18h18"/><path d="m19 9-5 5-4-4-3 3"/></svg>`;
    case "agents":
      return `<svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="5"/><path d="M20 21a8 8 0 0 0-16 0"/></svg>`;
    case "assets":
      return `<svg viewBox="0 0 24 24"><rect x="2" y="6" width="20" height="12" rx="2"/><path d="M12 12h.01"/><path d="M17 12h.01"/><path d="M7 12h.01"/></svg>`;
    case "entry-points":
      return `<svg viewBox="0 0 24 24"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>`;
    case "blast-radius":
      return `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>`;
    case "threats":
      return `<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><path d="m9 12 2 2 4-4"/></svg>`;
    case "safety-rules":
      return `<svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;
    case "emergency":
      return `<svg viewBox="0 0 24 24"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    case "timeline":
      return `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`;
    case "governance":
      return `<svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M16 13H8"/><path d="M16 17H8"/><path d="M10 9H8"/></svg>`;
    case "risk-history":
      return `<svg viewBox="0 0 24 24"><path d="M3 3v18h18"/><path d="M18 17V9"/><path d="M13 17V5"/><path d="M8 17v-3"/></svg>`;
    default:
      return `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/></svg>`;
  }
}
