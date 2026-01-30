import { Command } from "commander";
import { onboardCommand } from "./commands/onboard.js";
import { startCommand } from "./commands/start.js";
import { statusCommand } from "./commands/status.js";
import { scanCommand } from "./commands/scan.js";

const VERSION = "0.1.0";

function buildProgram(): Command {
  const program = new Command();

  program
    .name("og")
    .description(
      "OG Personal — The first guard agent for your personal AI assistant"
    )
    .version(VERSION, "-v, --version");

  // Register commands
  onboardCommand(program);
  startCommand(program);
  statusCommand(program);
  scanCommand(program);

  return program;
}

// Run the CLI
const program = buildProgram();
await program.parseAsync(process.argv);
