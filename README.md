# OG Personal

**OG Personal — The first guard agent for your personal AI assistant** - 24/7 security monitoring, risk detection, and auto-remediation for your AI agents.

OG Personal is the personal edition of [OpenGuardrails](https://openguardrails.com). OG = OpenGuardrails.

## Features

- **Real-time Monitoring**: Watch OpenClaw configuration and activity 24/7
- **Risk Assessment**: Combined blast radius and threat detection scoring
- **Threat Detection**:
  - **Protection** (attacks against agent): Prompt injection, system override, web attacks, MCP poisoning, malicious code
  - **Supervision** (agent mistakes): NSFW, PII, credentials, confidential data, off-topic
- **Web Dashboard**: Beautiful UI to monitor security status
- **Auto-Remediation**: Optional automatic blocking of high-risk threats
- **Chat Assistant**: Ask OG Personal about security concepts and recommendations

## Quick Start

```bash
# Install globally
npm install -g og-personal

# Set up with your API key
og onboard

# Start monitoring
og start
```

## Commands

| Command | Description |
|---------|-------------|
| `og onboard` | Set up OG Personal with your API key |
| `og start` | Start the 24/7 monitoring daemon |
| `og status` | Show current security status |
| `og scan` | Run a one-time security scan |

## Dashboard

Once running, access the dashboard at: **http://localhost:18790**

The dashboard includes:
- **Risk Overview**: Combined risk score and quick stats
- **Agents**: View all OpenClaw agents and their security posture
- **Blast Radius**: Visualize what OpenClaw can access
- **Threat Detection**: Protection and supervision detector status
- **Control**: Configure detection settings
- **Governance**: Audit logs and history

## Configuration

OG Personal stores its configuration at `~/.og-personal/config.json`.

### Detection Settings

```json
{
  "detectors": {
    "protection": {
      "promptInjection": true,
      "systemOverride": true,
      "webAttacks": true,
      "mcpPoisoning": true,
      "maliciousCode": true
    },
    "supervision": {
      "nsfw": true,
      "pii": true,
      "credentials": true,
      "confidential": true,
      "offTopic": false
    }
  }
}
```

### Sensitivity Levels

```json
{
  "sensitivity": {
    "promptInjection": 70,
    "pii": 80,
    "credentials": 90
  }
}
```

## Development

```bash
# Install dependencies
pnpm install
cd ui && pnpm install && cd ..

# Build
pnpm build
pnpm ui:build

# Run in development
pnpm dev

# Run UI dev server
pnpm ui:dev
```
