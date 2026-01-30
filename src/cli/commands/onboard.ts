import { Command } from "commander";
import * as p from "@clack/prompts";
import chalk from "chalk";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { loadConfig, saveConfig } from "../../config/io.js";
import { OG_PATHS, OPENCLAW_PATHS, getOpenClawConfigPath } from "../../config/paths.js";
import { OpenClawWatcher } from "../../agent/openclaw-watcher.js";
import { OGLLMClient } from "../../agent/og-llm-client.js";

export function onboardCommand(program: Command): void {
  program
    .command("onboard")
    .description("Set up OG Personal security monitoring")
    .option("--reset", "Reset existing configuration")
    .action(async (opts) => {
      await runOnboarding(opts.reset ?? false);
    });
}

async function runOnboarding(reset: boolean): Promise<void> {
  console.clear();

  p.intro(
    chalk.bold.red("   OG Personal   ") +
      chalk.dim(" - Security Agent Setup")
  );

  // Check if already configured
  const existingConfig = loadConfig();
  if (existingConfig.onboardingComplete && !reset) {
    const shouldContinue = await p.confirm({
      message: "OG Personal is already configured. Do you want to reconfigure?",
      initialValue: false,
    });

    if (p.isCancel(shouldContinue) || !shouldContinue) {
      p.outro("Setup cancelled. Run 'og start' to begin monitoring.");
      return;
    }
  }

  // Step 1: Check OpenClaw installation
  const openclawInstalled = OpenClawWatcher.isOpenClawInstalled();

  if (!openclawInstalled) {
    p.log.warn(
      chalk.yellow("OpenClaw is not installed at ") +
        chalk.cyan(OPENCLAW_PATHS.base)
    );
    p.log.info("OG Personal can still be configured, but monitoring will be limited.");
    p.log.info(
      "Install OpenClaw: " + chalk.cyan("npm install -g openclaw")
    );
  } else {
    p.log.success(
      chalk.green("OpenClaw detected at ") + chalk.cyan(OPENCLAW_PATHS.base)
    );
    const state = OpenClawWatcher.getState();
    p.log.info(
      `Found ${state.agents.length} agent(s) and ${state.sessions.length} session(s)`
    );
  }

  // Step 2: Get API key
  p.log.step("Configure OpenGuardrails API");
  p.log.info(chalk.dim("Get your API key at: ") + chalk.cyan("https://openguardrails.com"));

  const apiKey = await p.text({
    message: "Enter your OpenGuardrails API key:",
    placeholder: "sk-xxxxxxxxxxxxxxxxxxxx",
    validate: (value) => {
      if (!value || value.trim().length < 10) {
        return "Please enter a valid API key";
      }
      return undefined;
    },
  });

  if (p.isCancel(apiKey)) {
    p.cancel("Setup cancelled.");
    process.exit(0);
  }

  // Step 3: Test API connection
  const testSpinner = p.spinner();
  testSpinner.start("Testing API connection...");

  try {
    const client = new OGLLMClient({
      apiKey: apiKey.trim(),
      apiBaseUrl: existingConfig.apiBaseUrl,
      model: existingConfig.model,
    });

    // Quick test with a simple detection
    const result = await client.detect({
      type: "prompt-injection",
      content: "Hello, this is a test message.",
    });

    if (result.confidence === 0 && result.details?.error) {
      throw new Error(String(result.details.error));
    }

    testSpinner.stop("API connection successful!");
  } catch (err) {
    testSpinner.stop("API connection failed");
    p.log.error(chalk.red(`Error: ${err}`));
    p.log.info("Please check your API key and try again.");

    const continueAnyway = await p.confirm({
      message: "Continue setup anyway?",
      initialValue: false,
    });

    if (p.isCancel(continueAnyway) || !continueAnyway) {
      p.cancel("Setup cancelled.");
      process.exit(1);
    }
  }

  // Step 4: Configure notifications
  const notifications = await p.confirm({
    message: "Enable desktop notifications for security alerts?",
    initialValue: true,
  });

  if (p.isCancel(notifications)) {
    p.cancel("Setup cancelled.");
    process.exit(0);
  }

  // Step 5: Configure auto-remediation
  const autoRemediation = await p.confirm({
    message: "Enable auto-remediation for high-risk threats?",
    initialValue: false,
  });

  if (p.isCancel(autoRemediation)) {
    p.cancel("Setup cancelled.");
    process.exit(0);
  }

  // Step 6: Configure transparent proxy
  let proxyConfig = existingConfig.proxy;

  if (openclawInstalled) {
    p.log.step("Configure Security Proxy");
    p.log.info(
      chalk.dim(
        "OG Personal can act as a transparent proxy, intercepting all API traffic to OpenClaw\n" +
        "for security detection. Clients connect to the same port — no config changes needed."
      )
    );

    const enableProxy = await p.confirm({
      message: "Enable OG Personal as a transparent security proxy for OpenClaw?",
      initialValue: true,
    });

    if (p.isCancel(enableProxy)) {
      p.cancel("Setup cancelled.");
      process.exit(0);
    }

    if (enableProxy) {
      // Read OpenClaw config to detect current gateway port and auth token
      const openclawConfigPath = getOpenClawConfigPath();
      let openclawGatewayPort = 18789;
      let openclawAuthToken: string | undefined;

      if (existsSync(openclawConfigPath)) {
        try {
          const openclawRaw = readFileSync(openclawConfigPath, "utf-8");
          const openclawConf = JSON.parse(openclawRaw);

          // Detect gateway port
          if (openclawConf?.gateway?.port) {
            openclawGatewayPort = openclawConf.gateway.port;
          }

          // Detect auth token
          if (openclawConf?.gateway?.auth?.token) {
            openclawAuthToken = openclawConf.gateway.auth.token;
          }

          p.log.info(
            `Detected OpenClaw gateway on port ${chalk.cyan(String(openclawGatewayPort))}` +
            (openclawAuthToken ? ` with auth token` : "")
          );
        } catch {
          p.log.warn("Could not read OpenClaw config, using defaults.");
        }
      }

      const internalPort = 18780;

      const confirmProxy = await p.confirm({
        message: `OG Personal will take over port ${openclawGatewayPort} and move OpenClaw to port ${internalPort}. Proceed?`,
        initialValue: true,
      });

      if (p.isCancel(confirmProxy)) {
        p.cancel("Setup cancelled.");
        process.exit(0);
      }

      if (confirmProxy) {
        // Update OpenClaw config to use internal port
        if (existsSync(openclawConfigPath)) {
          try {
            const openclawRaw = readFileSync(openclawConfigPath, "utf-8");
            const openclawConf = JSON.parse(openclawRaw);

            if (!openclawConf.gateway) openclawConf.gateway = {};
            openclawConf.gateway.port = internalPort;

            writeFileSync(openclawConfigPath, JSON.stringify(openclawConf, null, 2) + "\n");
            p.log.success(
              `OpenClaw gateway port changed to ${chalk.cyan(String(internalPort))}`
            );
          } catch (err) {
            p.log.error(`Failed to update OpenClaw config: ${err}`);
            p.log.info("You may need to manually change OpenClaw's gateway port.");
          }
        }

        proxyConfig = {
          enabled: true,
          listenPort: openclawGatewayPort,
          openclawInternalPort: internalPort,
          openclawAuthToken,
        };

        p.log.success(
          `Proxy: port ${chalk.cyan(String(openclawGatewayPort))} (OG Personal) → port ${chalk.cyan(String(internalPort))} (OpenClaw)`
        );
      }
    }
  }

  // Step 7: Save configuration
  const saveSpinner = p.spinner();
  saveSpinner.start("Saving configuration...");

  // Ensure config directory exists
  if (!existsSync(OG_PATHS.base)) {
    mkdirSync(OG_PATHS.base, { recursive: true });
  }

  const config = {
    ...existingConfig,
    apiKey: apiKey.trim(),
    notifications: {
      desktop: Boolean(notifications),
      email: existingConfig.notifications.email,
    },
    autoRemediation: {
      enabled: Boolean(autoRemediation),
      blockHighRisk: Boolean(autoRemediation),
      notifyOnBlock: true,
    },
    proxy: proxyConfig,
    onboardingComplete: true,
  };

  saveConfig(config);
  saveSpinner.stop("Configuration saved!");

  // Step 7: Run initial scan
  if (openclawInstalled) {
    const runScan = await p.confirm({
      message: "Run initial security scan now?",
      initialValue: true,
    });

    if (!p.isCancel(runScan) && runScan) {
      const { OGAgent } = await import("../../agent/og-agent.js");
      const agent = new OGAgent();

      const scanSpinner = p.spinner();
      scanSpinner.start("Running security scan...");

      try {
        const assessment = await agent.runScan();
        scanSpinner.stop("Scan complete!");

        // Display results
        const levelColor =
          assessment.level === "high"
            ? chalk.red
            : assessment.level === "medium"
              ? chalk.yellow
              : assessment.level === "low"
                ? chalk.blue
                : chalk.green;

        p.log.info(
          `Risk Level: ${levelColor(assessment.level.toUpperCase())} (Score: ${assessment.score}/100)`
        );
        p.log.info(
          `Blast Radius: ${assessment.blastRadiusScore}/100 | Threats: ${assessment.threatScore}/100`
        );

        if (assessment.detections.some((d) => d.isRisk)) {
          p.log.warn("Security issues detected! Run 'og status' for details.");
        }
      } catch (err) {
        scanSpinner.stop("Scan failed");
        p.log.error(`Error: ${err}`);
      }
    }
  }

  // Done!
  console.log();
  p.outro(
    chalk.bold("Setup complete! ") +
      chalk.dim("Run ") +
      chalk.cyan("og start") +
      chalk.dim(" to begin monitoring.")
  );

  console.log();
  console.log(chalk.dim("Quick commands:"));
  console.log(chalk.cyan("  og start   ") + chalk.dim("- Start 24/7 monitoring daemon"));
  console.log(chalk.cyan("  og status  ") + chalk.dim("- View current security status"));
  console.log(chalk.cyan("  og scan    ") + chalk.dim("- Run a one-time security scan"));
  console.log();
  console.log(chalk.dim("Dashboard: ") + chalk.cyan("http://localhost:18790"));
  console.log();
}
