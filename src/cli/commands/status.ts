import { Command } from "commander";
import chalk from "chalk";
import { loadConfig, isConfigured, isOnboarded } from "../../config/io.js";
import { OpenClawWatcher } from "../../agent/openclaw-watcher.js";
import { OGAgent } from "../../agent/og-agent.js";

export function statusCommand(program: Command): void {
  program
    .command("status")
    .description("Show current security status")
    .option("--json", "Output as JSON")
    .action(async (opts) => {
      await runStatus(opts.json ?? false);
    });
}

async function runStatus(json: boolean): Promise<void> {
  const config = loadConfig();
  const openclawInstalled = OpenClawWatcher.isOpenClawInstalled();
  const openclawState = openclawInstalled ? OpenClawWatcher.getState() : null;

  // Build status object
  const status = {
    configured: isConfigured(),
    onboarded: isOnboarded(),
    openclaw: {
      installed: openclawInstalled,
      configExists: openclawState?.configExists ?? false,
      agentCount: openclawState?.agents.length ?? 0,
      sessionCount: openclawState?.sessions.length ?? 0,
    },
    monitoring: {
      watchFiles: config.scan.watchFiles,
      intervalMs: config.scan.intervalMs,
      lastScanAt: config.lastScanAt ?? null,
    },
    detectors: {
      protection: config.detectors.protection,
      supervision: config.detectors.supervision,
    },
    autoRemediation: config.autoRemediation,
    lastAssessment: null as Record<string, unknown> | null,
  };

  // Get last assessment if configured
  if (status.configured) {
    const agent = new OGAgent();
    const assessment = agent.getLastAssessment();
    if (assessment) {
      status.lastAssessment = {
        level: assessment.level,
        score: assessment.score,
        blastRadiusScore: assessment.blastRadiusScore,
        threatScore: assessment.threatScore,
        detectionsCount: assessment.detections.length,
        risksFound: assessment.detections.filter((d) => d.isRisk).length,
        timestamp: new Date(assessment.timestamp).toISOString(),
      };
    }
  }

  // Output
  if (json) {
    console.log(JSON.stringify(status, null, 2));
    return;
  }

  // Human-readable output
  console.log();
  console.log(
    chalk.bold.red("  OG Personal  ") + chalk.dim("- Security Status")
  );
  console.log();

  // Configuration status
  console.log(chalk.bold("Configuration"));
  console.log(
    `  ${status.configured ? chalk.green("Configured") : chalk.yellow("Not configured")}`
  );
  if (!status.onboarded) {
    console.log(
      chalk.dim("  Run ") + chalk.cyan("og onboard") + chalk.dim(" to set up")
    );
  }
  console.log();

  // OpenClaw status
  console.log(chalk.bold("OpenClaw"));
  if (status.openclaw.installed) {
    console.log(`  Status: ${chalk.green("Installed")}`);
    console.log(`  Config: ${status.openclaw.configExists ? chalk.green("Found") : chalk.yellow("Missing")}`);
    console.log(`  Agents: ${chalk.cyan(status.openclaw.agentCount)}`);
    console.log(`  Sessions: ${chalk.cyan(status.openclaw.sessionCount)}`);
  } else {
    console.log(`  Status: ${chalk.yellow("Not installed")}`);
  }
  console.log();

  // Monitoring status
  console.log(chalk.bold("Monitoring"));
  console.log(
    `  File watching: ${status.monitoring.watchFiles ? chalk.green("Enabled") : chalk.dim("Disabled")}`
  );
  console.log(`  Scan interval: ${chalk.cyan(status.monitoring.intervalMs / 1000 + "s")}`);
  if (status.monitoring.lastScanAt) {
    console.log(`  Last scan: ${chalk.dim(status.monitoring.lastScanAt)}`);
  }
  console.log();

  // Last assessment
  if (status.lastAssessment) {
    const assessment = status.lastAssessment;
    const levelColor =
      assessment.level === "high"
        ? chalk.red
        : assessment.level === "medium"
          ? chalk.yellow
          : assessment.level === "low"
            ? chalk.blue
            : chalk.green;

    console.log(chalk.bold("Risk Assessment"));
    console.log(
      `  Level: ${levelColor(String(assessment.level).toUpperCase())}`
    );
    console.log(`  Score: ${chalk.cyan(assessment.score + "/100")}`);
    console.log(`  Blast Radius: ${chalk.cyan(assessment.blastRadiusScore + "/100")}`);
    console.log(`  Threats: ${chalk.cyan(assessment.threatScore + "/100")}`);
    if (Number(assessment.risksFound) > 0) {
      console.log(
        `  Risks Found: ${chalk.red(assessment.risksFound)}`
      );
    }
    console.log();
  }

  // Detectors
  console.log(chalk.bold("Active Detectors"));
  console.log(chalk.dim("  Protection (attacks):"));
  const protection = status.detectors.protection;
  if (protection.promptInjection) console.log(`    ${chalk.green("")} Prompt Injection`);
  if (protection.systemOverride) console.log(`    ${chalk.green("")} System Override`);
  if (protection.webAttacks) console.log(`    ${chalk.green("")} Web Attacks`);
  if (protection.mcpPoisoning) console.log(`    ${chalk.green("")} MCP Poisoning`);
  if (protection.maliciousCode) console.log(`    ${chalk.green("")} Malicious Code`);

  console.log(chalk.dim("  Supervision (mistakes):"));
  const supervision = status.detectors.supervision;
  if (supervision.nsfw) console.log(`    ${chalk.green("")} NSFW`);
  if (supervision.pii) console.log(`    ${chalk.green("")} PII`);
  if (supervision.credentials) console.log(`    ${chalk.green("")} Credentials`);
  if (supervision.confidential) console.log(`    ${chalk.green("")} Confidential`);
  if (supervision.offTopic) console.log(`    ${chalk.green("")} Off-Topic`);
  console.log();

  // Quick actions
  console.log(chalk.dim("Quick actions:"));
  console.log(chalk.dim("  ") + chalk.cyan("og scan") + chalk.dim("   - Run security scan now"));
  console.log(chalk.dim("  ") + chalk.cyan("og start") + chalk.dim("  - Start monitoring daemon"));
  console.log();
}
