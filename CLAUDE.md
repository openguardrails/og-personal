# CLAUDE.md — OG Personal

## What This Project Is

OG Personal is a security agent for OpenClaw — a personal AI assistant runtime where users control agents via messaging apps (Telegram, Discord, WhatsApp, etc.) on a dedicated machine.

OG Personal is the personal edition of OpenGuardrails (OG = OpenGuardrails). There are three editions: OG Personal, OG Business, OG Enterprise. Website: OpenGuardrails.com.

The core problem: OpenClaw agents have real system access (shell, browser, file system, messaging) but ordinary users cannot understand the security implications. OG Personal makes agent security visible, controllable, and auditable for non-technical users.

OG Personal runs as a daemon alongside OpenClaw, providing:
- **Observability**: Asset discovery, entry point mapping, blast radius analysis
- **Threat Detection**: LLM-powered detection of 19 threat types (prompt injection, credential exposure, malicious code, etc.)
- **Controls**: Safety rules with confirmation gates, isolation policies, emergency kill switches
- **Governance**: Execution timeline replay, audit logs, risk history trends

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ CLI (og onboard / start / scan / status)                     │
│   src/cli/program.ts → src/cli/commands/*.ts                 │
├──────────────────────────────────────────────────────────────┤
│ OGAgent (core security engine)                               │
│   src/agent/og-agent.ts                                      │
│   ├── OpenClawWatcher  — file system monitor (chokidar)      │
│   │   src/agent/openclaw-watcher.ts                          │
│   └── OGLLMClient — threat detection                         │
│       src/agent/og-llm-client.ts                             │
├──────────────────────────────────────────────────────────────┤
│ Plugin (in-process OpenClaw plugin)                          │
│   src/plugin/index.ts — hooks into OpenClaw's plugin system  │
│   Registers 6 hooks: message_received, before_agent_start,   │
│   message_sending, before_tool_call, after_tool_call,        │
│   agent_end                                                  │
├──────────────────────────────────────────────────────────────┤
│ Gateway Server (HTTP + WebSocket)                            │
│   src/gateway/server.ts                                      │
│   Port 18790, serves REST API + WebSocket + static UI        │
├──────────────────────────────────────────────────────────────┤
│ Web Dashboard (Lit + Vite SPA)                               │
│   ui/src/ui/app.ts — single Lit component, all pages         │
│   ui/src/ui/navigation.ts — tab routing                      │
│   ui/src/ui/gateway.ts — WebSocket client                    │
│   ui/src/styles/ — CSS (base, layout, components)            │
└──────────────────────────────────────────────────────────────┘
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Runtime | Node.js >= 22.12.0 |
| Language | TypeScript (ES2022, NodeNext modules) |
| Package manager | pnpm 10.23.0 (do NOT use npm/yarn) |
| Backend framework | Raw Node.js http + ws (WebSocket) |
| LLM API | OpenAI-compatible client → OpenGuardrails (OpenGuardrails-Text) |
| Config validation | Zod |
| File watching | Chokidar |
| CLI | Commander + @clack/prompts |
| Frontend framework | Lit 3 (web components, no shadow DOM) |
| Frontend build | Vite 7 |
| Linter | oxlint |
| Formatter | oxfmt |
| Tests | vitest |

## Quick Start

```bash
# Install dependencies (both root and UI)
pnpm install
cd ui && pnpm install && cd ..

# Build everything
pnpm build          # TypeScript → dist/
pnpm ui:build       # Vite → ui/dist/

# Run in development
pnpm dev            # Backend via bun (hot reload)
pnpm ui:dev         # Frontend dev server at :5174 (proxies API to :18790)

# Run CLI
node og.mjs start   # Start monitoring daemon + dashboard at http://localhost:18790
node og.mjs scan    # One-time security scan
node og.mjs status  # Show current state
node og.mjs onboard # Interactive setup wizard
```

## Project Structure

```
og-personal/
├── src/
│   ├── index.ts                  # Public API exports
│   ├── agent/
│   │   ├── og-agent.ts           # Core: risk assessment, scan orchestration, event system
│   │   ├── og-llm-client.ts      # LLM detection engine (19 detection types, quick-check regex)
│   │   └── openclaw-watcher.ts   # File system monitor for OpenClaw state changes
│   ├── cli/
│   │   ├── program.ts            # CLI entry, registers all commands
│   │   └── commands/
│   │       ├── onboard.ts        # Setup wizard (API key, notifications, initial scan)
│   │       ├── start.ts          # Daemon: agent + watcher + gateway server
│   │       ├── status.ts         # Print current config/state/assessment
│   │       └── scan.ts           # One-time scan with JSON/verbose output
│   ├── config/
│   │   ├── schema.ts             # Zod schema (OGConfigSchema), defines all config fields
│   │   ├── io.ts                 # loadConfig / saveConfig / updateConfig
│   │   └── paths.ts              # OG_PATHS (~/.og-personal), OPENCLAW_PATHS (~/.openclaw)
│   ├── plugin/
│   │   └── index.ts              # OpenClaw plugin entry — registers security hooks
│   └── gateway/
│       └── server.ts             # HTTP API + WebSocket + static file serving
├── ui/
│   ├── src/
│   │   ├── main.ts               # Registers <og-app> custom element
│   │   └── ui/
│   │       ├── app.ts            # Main component (~1620 lines), ALL pages rendered here
│   │       ├── navigation.ts     # Tab definitions, routing, icons, titles
│   │       ├── gateway.ts        # WebSocket client (connect, reconnect, message handlers)
│   │       └── theme.ts          # Dark/light theme toggle
│   ├── src/styles/
│   │   ├── base.css              # CSS variables, fonts, colors, animations
│   │   ├── layout.css            # Shell grid, topbar, nav sidebar, content area
│   │   └── components.css        # Cards, badges, buttons, toggles, timeline, asset cards
│   ├── index.html                # SPA entry
│   ├── vite.config.ts            # Build config, dev proxy to :18790
│   └── package.json              # UI deps (lit, vite)
├── dist/                         # Compiled JS output (gitignored in production)
├── openclaw.plugin.json          # Plugin manifest for OpenClaw
├── og.mjs                        # CLI binary entry point
├── package.json                  # Root deps, scripts, bin field
└── tsconfig.json                 # strict, ES2022, NodeNext
```

## Configuration

**OG Personal config**: `~/.og-personal/config.json` (Zod-validated, see `src/config/schema.ts`)

Key fields:
- `apiKey` — OpenGuardrails API key for LLM detection
- `apiBaseUrl` — API endpoint (default: `https://api.openguardrails.com/v1`)
- `model` — LLM model (default: `OpenGuardrails-Text`)
- `gatewayPort` — Dashboard port (default: `18790`)
- `detectors.protection.*` — Toggle attack detectors (prompt injection, system override, web attacks, MCP poisoning, malicious code)
- `detectors.supervision.*` — Toggle supervision detectors (NSFW, PII, credentials, confidential, off-topic)
- `sensitivity.*` — Detection thresholds (0-100)
- `autoRemediation.*` — Auto-block settings
- `scan.intervalMs` — Periodic scan interval (default: 30s)
- `scan.watchFiles` — Enable chokidar file watching
- `proxy.enabled` — Enable transparent proxy mode
- `proxy.listenPort` — Port OG Personal listens on (default: 18789)
- `proxy.openclawInternalPort` — Port OpenClaw is moved to (default: 18780)
- `proxy.openclawAuthToken` — OpenClaw gateway auth token

**OpenClaw state**: `~/.openclaw/` (read-only, OG Personal monitors but does not modify)
- `openclaw.json` — Main OpenClaw config (legacy: `clawdbot.json`, `moltbot.json`)
- `agents/{id}/agent.json` — Per-agent config
- `agents/{id}/sessions/*.jsonl` — Session conversation logs
- `credentials/` — Stored tokens and API keys

**Legacy path resolution**: OG Personal auto-detects `~/.openclaw/`, `~/.clawdbot/`, `~/.moltbot/` (in priority order) for backward compatibility with renamed directories.

## Risk Assessment Model

```
Blast Radius Score (0-100) = connections * 15 + MCP tools * 10 + skills * 5 + file access * 20
Threat Score (0-100) = sum of detections (high: +40, medium: +20, low: +10)
Combined Score (0-100) = threat * 0.6 + blast_radius * 0.4

Risk Level: high (>=70), medium (>=40), low (>=10), none (<10)
```

## Gateway API

**HTTP** (port 18790):
- `GET /api/status` — Config state + last assessment
- `GET /api/openclaw/state` — Full OpenClaw state snapshot
- `POST /api/scan` — Trigger scan, returns assessment
- `POST /api/analyze` — Body: `{content, types?}`, deep LLM analysis
- `POST /api/quick-check` — Body: `{content}`, fast regex check

**WebSocket** (`/ws`):
- Client sends: `get-status`, `get-openclaw-state`, `run-scan`, `analyze`, `quick-check`
- Server sends: `hello`, `status`, `openclaw-state`, `scan-result`, `analyze-result`, `quick-check-result`, `agent-event`

## Dashboard Navigation

```
Chat
  └── Chat with OG Personal    — AI security assistant (coming soon)

Observability
  ├── Dashboard              — Risk score, agents, assets exposed, recent activity
  ├── Agents                 — Agent inventory with session counts
  ├── Assets                 — Apps, tools, files, credentials, system permissions
  ├── Entry Points           — Instruction entries (messaging) + content entries (web/files/email)
  └── Blast Radius           — Connections and MCP tools exposure

Protect
  ├── Threat Detection       — Protection (5 detectors) + Supervision (5 detectors)
  ├── Safety Rules           — Toggle-based policies (confirmation, isolation, communication)
  └── Emergency Controls     — Pause agents, revoke credentials, rollback session

Govern
  ├── Execution Timeline     — Step-by-step replay of agent decisions and tool calls
  ├── Audit Log              — Security events
  └── Risk History           — 7-day risk trend chart + period summary
```

## Core Security Design — Hook LLM Input/Output

OG Personal provides four layers of security for OpenClaw:

1. **Hook LLM input/output** — AI guardrails protecting against OG Top 10 threats (v1, priority)
2. **Scan configs & exposure** — Static analysis of config files, service exposure, credentials
3. **Security penetration testing** — Active testing of agent attack surface
4. **Security skills & MCP** — Skills and MCP tools for checking URLs, emails, files (via ogserver)

### V1 Focus: Hook LLM Input/Output

OG Personal registers as an **OpenClaw plugin** to intercept all LLM interactions in real-time. It uses OpenClaw's typed plugin hook system to scan user input, LLM output, and tool calls against the OG Top 10 threat categories.

```
User Message (Telegram/Discord/etc)
    │
    ▼
┌─────────────────────────────────────────────┐
│ message_received hook                       │
│   OG Personal scans input for:              │
│   - Prompt injection                        │
│   - System override attempts                │
│   - Malicious content                       │
└─────────────────┬───────────────────────────┘
                  │
    ▼
┌─────────────────────────────────────────────┐
│ before_agent_start hook                     │
│   OG Personal:                              │
│   - Injects security context into prompt    │
│   - Monitors system prompt integrity        │
│   - Records session baseline                │
└─────────────────┬───────────────────────────┘
                  │
    ▼
    LLM API Call (Anthropic/OpenAI/etc)
                  │
    ▼
┌─────────────────────────────────────────────┐
│ message_sending hook                        │
│   OG Personal scans LLM output for:        │
│   - Credential leakage                      │
│   - PII exposure                            │
│   - NSFW / harmful content                  │
│   - Can BLOCK or MODIFY response            │
└─────────────────┬───────────────────────────┘
                  │
    ▼
┌─────────────────────────────────────────────┐
│ before_tool_call hook                       │
│   OG Personal scans tool calls for:        │
│   - Credential leakage in params            │
│   - Malicious code execution                │
│   - File system destructive ops             │
│   - Network exfiltration                    │
│   - Can BLOCK tool execution                │
│   Deep-scans high-risk tools: bash, shell,  │
│   write_file, delete_file, http_request,    │
│   fetch, curl, execute, run_command         │
└─────────────────┬───────────────────────────┘
                  │
    ▼
┌─────────────────────────────────────────────┐
│ after_tool_call hook                        │
│   OG Personal:                              │
│   - Logs tool execution to audit trail      │
│   - Records errors and duration             │
└─────────────────┬───────────────────────────┘
                  │
    ▼
    Response sent to user
                  │
    ▼
┌─────────────────────────────────────────────┐
│ agent_end hook                              │
│   OG Personal:                              │
│   - Full conversation threat assessment     │
│   - Audit log entry                         │
│   - Risk score update                       │
└─────────────────────────────────────────────┘
```

### OpenClaw Plugin Hook System

OpenClaw has a plugin system at `openclaw/src/plugins/` with 14 hook types. OG Personal uses the typed hook API:

```typescript
api.on("hook_name", async (event, ctx) => { ... }, { priority: -100 });
```

**Hook types are fully typed** — each hook has specific event, context, and result types defined in `openclaw/src/plugins/types.ts`. The `api.on()` method uses generic constraints to enforce type safety:

```typescript
on: <K extends PluginHookName>(
  hookName: K,
  handler: PluginHookHandlerMap[K],
  opts?: { priority?: number },
) => void;
```

**Hook status in OpenClaw codebase:**

| Hook | Type | Wired Up | OG Personal Use |
|------|------|----------|-----------------|
| `before_agent_start` | modifying | YES | Inject security context, monitor system prompt |
| `message_received` | void | YES | Scan user input for injection/attacks |
| `agent_end` | void | YES | Post-conversation threat assessment, audit |
| `tool_result_persist` | sync | YES | Sanitize sensitive data in transcript |
| `message_sending` | modifying | NO — needs wiring | Scan/block LLM output (credentials, PII, NSFW) |
| `before_tool_call` | modifying | NO — needs wiring | Scan/block dangerous tool calls |
| `after_tool_call` | void | NO | Log tool execution results |
| `message_sent` | void | NO | Confirm delivery |
| `session_start/end` | void | NO | Session lifecycle tracking |
| `gateway_start/stop` | void | NO | System lifecycle |
| `before/after_compaction` | void | NO | Context window monitoring |

**Key files in OpenClaw:**
- Hook runner: `openclaw/src/plugins/hook-runner-global.ts` → `getGlobalHookRunner()`
- Hook execution: `openclaw/src/plugins/hooks.ts` → `runModifyingHook()`, `runVoidHook()`
- Hook types: `openclaw/src/plugins/types.ts` → `PluginHookName`, `PluginHookHandlerMap`
- Plugin registration: `openclaw/src/plugins/registry.ts` → `api.on(hookName, handler)`
- Invocation — before_agent_start: `openclaw/src/agents/pi-embedded-runner/run/attempt.ts:690`
- Invocation — agent_end: `openclaw/src/agents/pi-embedded-runner/run/attempt.ts:816`
- Invocation — message_received: `openclaw/src/auto-reply/reply/dispatch-from-config.ts:156`
- Invocation — tool_result_persist: `openclaw/src/agents/session-tool-result-guard-wrapper.ts:30`

### V1 Implementation Requirements

1. **OG Personal as OpenClaw plugin**: OG Personal is loaded as an in-process plugin by OpenClaw (no external hook registration API exists). Plugin entry point at `src/plugin/index.ts`, manifest at `openclaw.plugin.json`.

2. **Wire up missing hooks in OpenClaw**: `message_sending` and `before_tool_call` are defined but never invoked. Add invocation calls at:
   - `message_sending`: in message-tool.ts before `sendMessage()` — modifying hook, can return `{ cancel: true }` to block or `{ content: "..." }` to modify
   - `before_tool_call`: in pi-embedded-subscribe.handlers.tools.ts before tool execution — modifying hook, can return `{ block: true, blockReason: "..." }`

3. **Detection via ogserver**: Hook handlers call ogserver's security API (not OG Personal's local LLM client) for real-time detection. ogserver provides the OpenGuardrails detection engine.

4. **Quick-check fast path**: Use local regex patterns (quick-check) for obvious threats to avoid API latency on every message. Only call ogserver for ambiguous content.

5. **Audit trail**: Every hook invocation logs to `~/.og-personal/audit.jsonl` with timestamp, hook type, detection results, and action taken (allow/block/modify).

### Hook Handler Signatures

```typescript
// before_agent_start — inject security rules into system prompt
api.on("before_agent_start", async (event: PluginHookBeforeAgentStartEvent, ctx: PluginHookAgentContext) => {
  // event.prompt: string, event.messages?: unknown[]
  // ctx.agentId?, ctx.sessionKey?, ctx.workspaceDir?, ctx.messageProvider?
  // Return: { systemPrompt?: string, prependContext?: string }
});

// message_received — scan user input (fire-and-forget, cannot block)
api.on("message_received", async (event: PluginHookMessageReceivedEvent, ctx: PluginHookMessageContext) => {
  // event.from: string, event.content: string, event.timestamp?, event.metadata?
  // ctx.channelId: string, ctx.accountId?, ctx.conversationId?
  // Return: void (alert only, cannot block at this hook)
});

// message_sending — scan and optionally block LLM output
api.on("message_sending", async (event: PluginHookMessageSendingEvent, ctx: PluginHookMessageContext) => {
  // event.to: string, event.content: string, event.metadata?
  // Return: { content?: string, cancel?: boolean }
});

// before_tool_call — scan and optionally block tool execution
api.on("before_tool_call", async (event: PluginHookBeforeToolCallEvent, ctx: PluginHookToolContext) => {
  // event.toolName: string, event.params: Record<string, unknown>
  // ctx.agentId?, ctx.sessionKey?, ctx.toolName: string
  // Return: { block?: boolean, blockReason?: string, params?: Record<string, unknown> }
});

// after_tool_call — log tool execution for audit trail
api.on("after_tool_call", async (event: PluginHookAfterToolCallEvent, ctx: PluginHookToolContext) => {
  // event.toolName: string, event.params: Record, event.result?, event.error?, event.durationMs?
  // Return: void
});

// agent_end — post-conversation analysis
api.on("agent_end", async (event: PluginHookAgentEndEvent, ctx: PluginHookAgentContext) => {
  // event.messages: unknown[], event.success: boolean, event.error?: string, event.durationMs?: number
  // Return: void
});
```

## Current Implementation Gaps

Three capabilities are designed in the UI but lack backend enforcement:

### 1. Safety Rules — UI only, no enforcement engine
- Frontend toggles exist in `app.ts` (`safetyRules` property) but state is in-memory only
- `schema.ts` has no `safetyRules` field — rules are not persisted
- No hook/middleware system to intercept OpenClaw actions before execution
- No confirmation protocol between OG Personal and OpenClaw

### 2. Execution Timeline — UI mockup, no data pipeline
- Timeline renders demo data from `getTimelineSessions()` hardcoded method
- No API endpoint or WebSocket message type for timeline data
- No parser to extract structured execution steps from OpenClaw session JSONL files
- `audit.jsonl` records OG Personal scan events only, not OpenClaw execution steps

### 3. Preset Scenarios — not implemented
- No scenario templates (e.g. "Personal Assistant Mode", "Developer Mode")
- No one-click configuration bundles
- No high-frequency task presets

## Key Patterns

- **Event-driven**: `OGAgent` and `OpenClawWatcher` use `onEvent(handler)` / `emit(event)` pattern
- **No shadow DOM**: `OGApp.createRenderRoot()` returns `this` — all CSS is global
- **Single-file UI**: All pages are render methods in `app.ts` (not separate components)
- **Zod-first config**: Schema defines defaults, `loadConfig()` returns validated config or defaults
- **SPA routing**: `navigation.ts` maps URL paths to tabs, server falls back to `index.html`
- **Two-tier detection**: Fast regex quick-check first, then optional deep LLM detection via API
- **Plugin types duplicated**: Hook types from OpenClaw are duplicated in `src/plugin/index.ts` to avoid build dependency on OpenClaw source

## Common Tasks

### Add a new dashboard page
1. Add tab name to `Tab` type union in `navigation.ts`
2. Add to `TAB_GROUPS`, `TAB_PATHS` in same file
3. Add `titleForTab`, `subtitleForTab`, `iconForTab` cases
4. Add `case` in `renderContent()` in `app.ts`
5. Add `private renderMyPage()` method in `app.ts`

### Add a new detection type
1. Add type to `DetectionType` union in `og-llm-client.ts`
2. Add system prompt in `getSystemPrompt()` switch case
3. Add to detector toggles in `schema.ts` if user-configurable
4. Update threat detection UI in `renderThreats()` in `app.ts`

### Add a new config field
1. Add field to `OGConfigSchema` in `schema.ts` with Zod type + default
2. The `OGConfig` type is auto-inferred — no manual type update needed
3. Access via `agent.getConfig().myField` or `loadConfig().myField`

### Add a new WebSocket message type
1. Add handler case in `handleWebSocketMessage()` in `server.ts`
2. Add corresponding send in gateway client (`ui/src/ui/gateway.ts`)
3. Handle response in `handleMessage()` in `app.ts`

### Add a new API endpoint
1. Add case in `handleApiRequest()` switch in `server.ts`
2. Follow existing pattern: parse body for POST, call agent method, `sendJson()` result

### Add a new plugin hook
1. Add typed event/context/result types in `src/plugin/index.ts` (mirror from `openclaw/src/plugins/types.ts`)
2. Add handler signature to local `PluginHookHandlerMap`
3. Register the hook via `api.on("hook_name", handler, { priority: -100 })`
4. Write audit entry with `writeAuditEntry()`

## Build & Test

```bash
pnpm build              # Compile backend TypeScript
pnpm ui:build           # Build frontend (Vite)
pnpm lint               # Lint with oxlint
pnpm format             # Check formatting with oxfmt
pnpm format:fix         # Auto-fix formatting
pnpm test               # Run tests (vitest)
pnpm test:watch         # Tests in watch mode
```

Type-check without emitting: `npx tsc --noEmit`

## File Paths at Runtime

| Path | Purpose |
|------|---------|
| `~/.og-personal/config.json` | OG Personal configuration (Zod-validated) |
| `~/.og-personal/audit.jsonl` | Security event audit log |
| `~/.og-personal/risk-history.db` | Risk score history |
| `~/.openclaw/` | OpenClaw base directory (read-only) |
| `~/.openclaw/openclaw.json` | OpenClaw main config |
| `~/.openclaw/agents/` | Agent configs and sessions |
| `~/.openclaw/credentials/` | Stored tokens and API keys |

**Legacy paths** (auto-detected for backward compatibility):
| Path | Purpose |
|------|---------|
| `~/.clawdbot/` | Legacy OpenClaw base directory |
| `~/.clawdbot/clawdbot.json` | Legacy config |
| `~/.moltbot/` | Legacy base directory |

## Naming History

The upstream project was renamed: **MoltBot** → **OpenClaw**.
The guard agent was renamed: **OpenClawGuard** → **OG Personal** (OG = OpenGuardrails).

- Config directory: `~/.OpenClawGuard/` → `~/.og-personal/`
- CLI binary: `openclawguard.mjs` → `og.mjs`
- CLI command: `openclawguard` → `og`
- Class names: `OGAgent` (was `OpenClawGuardAgent`), `OGLLMClient` (was `OpenClawGuardLLMClient`)
- Config types: `OGConfig` (was `OpenClawGuardConfig`), `OGConfigSchema` (was `OpenClawGuardConfigSchema`)
- Path constants: `OG_PATHS` (was `OpenClawGuard_PATHS`)
- Source files: `og-agent.ts` (was `openclawguard-agent.ts`), `og-llm-client.ts` (was `openclawguard-llm-client.ts`)
- Custom element: `<og-app>` (was `<OpenClawGuard-app>`)
- Log prefix: `[OG]` (was `[OpenClawGuard]`)
- Env vars: `OG_API_KEY` (was `OpenClawGuard_API_KEY`)
- Plugin id: `og-personal` (was `openclawguard`)
- OpenClaw class names: `OpenClawWatcher` (was `MoltbotWatcher`), `OpenClawState` (was `MoltbotState`)
- OpenClaw agent methods: `isOpenClawInstalled()` (was `isMoltbotInstalled()`), `getOpenClawState()` (was `getMoltbotState()`)
- API routes: `/api/openclaw/state` (was `/api/openclaw/state`)
- WebSocket: `get-openclaw-state` / `openclaw-state` (was `get-openclaw-state` / `openclaw-state`)
- Config fields: `proxy.openclawInternalPort` (was `proxy.moltbotInternalPort`), `proxy.openclawAuthToken` (was `proxy.moltbotAuthToken`)

Legacy aliases are exported from `src/agent/openclaw-watcher.ts` and `src/config/paths.ts` for backward compatibility.
