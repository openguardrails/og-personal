import { Command } from "commander";
import { fork } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import chalk from "chalk";
import { loadConfig, isConfigured } from "../../config/io.js";
import { OGAgent } from "../../agent/og-agent.js";
import { createGatewayServer } from "../../gateway/server.js";

export function startCommand(program: Command): void {
  program
    .command("start")
    .description("Start the OG Personal security monitoring daemon")
    .option("-p, --port <port>", "Gateway port", "18790")
    .option("--no-ui", "Disable web UI")
    .option("--no-watch", "Disable file watching")
    .action(async (opts) => {
      await runStart(opts);
    });
}

interface StartOptions {
  port: string;
  ui: boolean;
  watch: boolean;
}

async function runStart(opts: StartOptions): Promise<void> {
  // Check if configured
  if (!isConfigured()) {
    console.log(chalk.yellow("OG Personal is not configured."));
    console.log(
      chalk.dim("Run ") + chalk.cyan("og onboard") + chalk.dim(" to set up.")
    );
    process.exit(1);
  }

  const config = loadConfig();
  const port = parseInt(opts.port, 10) || config.gatewayPort;

  console.log();
  console.log(
    chalk.bold.red("  OG Personal  ") +
      chalk.dim("- Security Agent v0.1.0")
  );
  console.log();

  // Create and start the agent
  const agent = new OGAgent();

  if (!opts.watch) {
    agent.updateConfig({ scan: { ...config.scan, watchFiles: false } });
  }

  // Set up event handlers
  agent.onEvent((event) => {
    switch (event.type) {
      case "started":
        console.log(chalk.green("[OG] Security agent started"));
        break;
      case "stopped":
        console.log(chalk.yellow("[OG] Security agent stopped"));
        break;
      case "scan-started":
        console.log(chalk.dim("[OG] Running security scan..."));
        break;
      case "scan-completed": {
        const { assessment } = event;
        const levelColor =
          assessment.level === "high"
            ? chalk.red
            : assessment.level === "medium"
              ? chalk.yellow
              : assessment.level === "low"
                ? chalk.blue
                : chalk.green;
        console.log(
          chalk.dim("[OG] Scan complete: ") +
            levelColor(`${assessment.level.toUpperCase()} (${assessment.score}/100)`)
        );
        break;
      }
      case "risk-detected":
        console.log(
          chalk.red(`[OG] Risk detected: ${event.detection.type}`) +
            chalk.dim(` (${event.detection.riskLevel})`)
        );
        break;
      case "openclaw-changed":
        console.log(
          chalk.dim(`[OG] OpenClaw ${event.event.type}: `) +
            chalk.cyan(event.event.path)
        );
        break;
      case "error":
        console.error(chalk.red(`[OG] Error: ${event.error.message}`));
        break;
    }
  });

  // Start the agent
  agent.start();

  // Start the gateway server
  if (opts.ui) {
    try {
      const server = await createGatewayServer(agent, port);
      console.log(
        chalk.dim("[OG] Dashboard: ") + chalk.cyan(`http://localhost:${port}`)
      );
    } catch (err) {
      console.error(chalk.red(`[OG] Failed to start gateway: ${err}`));
      await agent.stop();
      process.exit(1);
    }
  }

  // Start transparent proxy if enabled
  if (config.proxy.enabled) {
    try {
      const proxyEnv: Record<string, string> = {
        OG_API_KEY: config.apiKey ?? "",
        OG_API_BASE_URL: config.apiBaseUrl,
        OG_PROXY_ENABLED: "true",
        OG_PROXY_LISTEN_PORT: String(config.proxy.listenPort),
        OG_OPENCLAW_UPSTREAM_PORT: String(config.proxy.openclawInternalPort),
      };
      if (config.proxy.openclawAuthToken) {
        proxyEnv.OG_OPENCLAW_AUTH_TOKEN = config.proxy.openclawAuthToken;
      }

      // Find ogserver entry point relative to this file
      // In built output: dist/cli/commands/start.js → need ogserver/dist/index.js
      // Resolve from project root
      const thisDir = dirname(fileURLToPath(import.meta.url));
      const projectRoot = join(thisDir, "..", "..", "..");
      const serverEntry = join(projectRoot, "ogserver", "dist", "index.js");

      const child = fork(serverEntry, [], {
        env: { ...process.env, ...proxyEnv },
        stdio: "pipe",
      });

      child.stdout?.on("data", (data: Buffer) => {
        const lines = data.toString().trim().split("\n");
        for (const line of lines) {
          console.log(chalk.dim("[proxy] ") + line);
        }
      });

      child.stderr?.on("data", (data: Buffer) => {
        const lines = data.toString().trim().split("\n");
        for (const line of lines) {
          console.error(chalk.red("[proxy] ") + line);
        }
      });

      child.on("exit", (code) => {
        if (code !== 0) {
          console.error(chalk.red(`[OG] Proxy process exited with code ${code}`));
        }
      });

      console.log(
        chalk.green("[OG] Security proxy active on port ") +
          chalk.cyan(String(config.proxy.listenPort)) +
          chalk.green(" → OpenClaw on ") +
          chalk.cyan(String(config.proxy.openclawInternalPort))
      );

      // Kill proxy child on exit
      process.on("exit", () => {
        child.kill();
      });
    } catch (err) {
      console.error(chalk.red(`[OG] Failed to start proxy: ${err}`));
    }
  }

  // Status summary
  console.log();
  console.log(chalk.dim("Monitoring OpenClaw for security threats..."));
  console.log(chalk.dim("Press Ctrl+C to stop."));
  console.log();

  // Handle graceful shutdown
  process.on("SIGINT", async () => {
    console.log();
    console.log(chalk.dim("[OG] Shutting down..."));
    await agent.stop();
    process.exit(0);
  });

  process.on("SIGTERM", async () => {
    await agent.stop();
    process.exit(0);
  });
}
