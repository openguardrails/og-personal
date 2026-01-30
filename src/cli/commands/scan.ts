import { Command } from "commander";
import chalk from "chalk";
import { isConfigured } from "../../config/io.js";
import { OGAgent } from "../../agent/og-agent.js";
import { OpenClawWatcher } from "../../agent/openclaw-watcher.js";

export function scanCommand(program: Command): void {
  program
    .command("scan")
    .description("Run a one-time security scan")
    .option("--json", "Output as JSON")
    .option("--verbose", "Show detailed detection results")
    .action(async (opts) => {
      await runScan(opts.json ?? false, opts.verbose ?? false);
    });
}

async function runScan(json: boolean, verbose: boolean): Promise<void> {
  // Check if configured
  if (!isConfigured()) {
    if (json) {
      console.log(
        JSON.stringify({ error: "Not configured", code: "NOT_CONFIGURED" })
      );
    } else {
      console.log(chalk.yellow("OG Personal is not configured."));
      console.log(
        chalk.dim("Run ") + chalk.cyan("og onboard") + chalk.dim(" to set up.")
      );
    }
    process.exit(1);
  }

  // Check if OpenClaw is installed
  if (!OpenClawWatcher.isOpenClawInstalled()) {
    if (json) {
      console.log(
        JSON.stringify({
          error: "OpenClaw not installed",
          code: "OPENCLAW_NOT_FOUND",
        })
      );
    } else {
      console.log(chalk.yellow("OpenClaw is not installed."));
      console.log(
        chalk.dim("Install OpenClaw: ") + chalk.cyan("npm install -g openclaw")
      );
    }
    process.exit(1);
  }

  if (!json) {
    console.log();
    console.log(
      chalk.bold.red("  OG Personal  ") + chalk.dim("- Security Scan")
    );
    console.log();
    console.log(chalk.dim("Running security scan..."));
    console.log();
  }

  // Create agent and run scan
  const agent = new OGAgent();

  try {
    const assessment = await agent.runScan();

    if (json) {
      console.log(
        JSON.stringify(
          {
            level: assessment.level,
            score: assessment.score,
            blastRadiusScore: assessment.blastRadiusScore,
            threatScore: assessment.threatScore,
            detections: assessment.detections,
            timestamp: new Date(assessment.timestamp).toISOString(),
          },
          null,
          2
        )
      );
      return;
    }

    // Human-readable output
    const levelColor =
      assessment.level === "high"
        ? chalk.red
        : assessment.level === "medium"
          ? chalk.yellow
          : assessment.level === "low"
            ? chalk.blue
            : chalk.green;

    // Overall result box
    console.log(chalk.bold("Risk Assessment"));
    console.log(
      `  Level: ${levelColor(assessment.level.toUpperCase())}`
    );
    console.log(`  Score: ${chalk.cyan(assessment.score + "/100")}`);
    console.log();

    // Breakdown
    console.log(chalk.bold("Breakdown"));
    console.log(`  Blast Radius: ${formatScore(assessment.blastRadiusScore)}`);
    console.log(`  Threat Score: ${formatScore(assessment.threatScore)}`);
    console.log();

    // OpenClaw state
    const state = OpenClawWatcher.getState();
    console.log(chalk.bold("OpenClaw State"));
    console.log(`  Agents: ${chalk.cyan(state.agents.length)}`);
    console.log(`  Sessions: ${chalk.cyan(state.sessions.length)}`);
    console.log(`  Credentials: ${chalk.cyan(state.credentialFiles.length)} files`);
    console.log();

    // Detections
    const riskyDetections = assessment.detections.filter((d) => d.isRisk);
    if (riskyDetections.length > 0) {
      console.log(chalk.bold.red("Risks Found"));
      for (const detection of riskyDetections) {
        const detectionColor =
          detection.riskLevel === "high"
            ? chalk.red
            : detection.riskLevel === "medium"
              ? chalk.yellow
              : chalk.blue;

        console.log(
          `  ${detectionColor("")} ${detection.type} ` +
            chalk.dim(`(${detection.riskLevel}, ${detection.confidence}% confidence)`)
        );

        if (verbose && detection.details) {
          const explanation =
            (detection.details as Record<string, unknown>).explanation ??
            (detection.details as Record<string, unknown>).issues;
          if (explanation) {
            console.log(chalk.dim(`    ${explanation}`));
          }
        }
      }
      console.log();
    } else {
      console.log(chalk.green("No immediate risks detected!"));
      console.log();
    }

    // Recommendations
    if (assessment.level !== "none") {
      console.log(chalk.bold("Recommendations"));
      if (assessment.blastRadiusScore > 50) {
        console.log(
          chalk.dim("  - Consider reducing the number of connected services")
        );
        console.log(chalk.dim("  - Review MCP tool permissions"));
      }
      if (assessment.threatScore > 30) {
        console.log(
          chalk.dim("  - Review detected threats in the dashboard")
        );
        console.log(chalk.dim("  - Enable auto-remediation for high-risk threats"));
      }
      console.log();
    }

    // Footer
    console.log(
      chalk.dim("Run ") +
        chalk.cyan("og start") +
        chalk.dim(" to enable continuous monitoring")
    );
    console.log(
      chalk.dim("Dashboard: ") + chalk.cyan("http://localhost:18790")
    );
    console.log();
  } catch (err) {
    if (json) {
      console.log(JSON.stringify({ error: String(err), code: "SCAN_FAILED" }));
    } else {
      console.error(chalk.red(`Scan failed: ${err}`));
    }
    process.exit(1);
  }
}

function formatScore(score: number): string {
  if (score >= 70) return chalk.red(`${score}/100`);
  if (score >= 40) return chalk.yellow(`${score}/100`);
  if (score >= 10) return chalk.blue(`${score}/100`);
  return chalk.green(`${score}/100`);
}
