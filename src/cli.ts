#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runMcp } from "./mcp.js";
import { VERSION } from "./version.js";

const USAGE = `cbp-guard ${VERSION}

Usage:
  cbp-guard mcp        Start the stdio MCP server (tools: wallet_check, gate, peer_challenge)
  cbp-guard --version  Print the version

Environment:
  CBP_GUARD_PRIVATE_KEY  Required for "mcp": private key of YOUR wallet that pays for each check
                         (x402, USDC on Base). Never logged.
  CBP_GUARD_BASE_URL     Optional; default https://certbeforepay.com
`;

export async function main(argv: string[]): Promise<number> {
  const cmd = argv[0];
  if (cmd === "--version" || cmd === "-v") {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (cmd === "mcp") {
    try {
      await runMcp();
      return 0;
    } catch (err) {
      // Messages are ours and never contain the key.
      process.stderr.write(`${err instanceof Error ? err.message : "cbp-guard: failed to start"}\n`);
      return 1;
    }
  }
  process.stderr.write(USAGE);
  return cmd === undefined || cmd === "--help" || cmd === "-h" ? 0 : 2;
}

function invokedDirectly(): boolean {
  try {
    return !!process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  main(process.argv.slice(2)).then((code) => {
    if (code !== 0) process.exit(code);
  });
}
