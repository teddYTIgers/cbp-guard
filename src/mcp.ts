/**
 * Stdio MCP server: tools wallet_check, gate and peer_challenge.
 * Each tool calls the live CertBeforePay HTTP endpoint and pays with the caller's own key
 * (CBP_GUARD_PRIVATE_KEY) via x402. The key is never logged or returned. Spend is capped per
 * UTC day per process (CBP_GUARD_DAILY_BUDGET_USD, default $1.00), reserved before signing.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { DEFAULT_DAILY_BUDGET_USD, SpendBudget } from "./budget.js";
import { CbpClient, CbpError, KNOWN_RECIPIENTS_MAX, type PaymentClientLike } from "./client.js";
import { VERSION } from "./version.js";

export const KEY_ENV = "CBP_GUARD_PRIVATE_KEY";
export const BASE_URL_ENV = "CBP_GUARD_BASE_URL";
export const BUDGET_ENV = "CBP_GUARD_DAILY_BUDGET_USD";

const INVALID_KEY = `cbp-guard: ${KEY_ENV} is not a valid secp256k1 private key`;

const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/, "0x + 40 hex");

export const walletCheckShape = {
  address: address.describe("Destination 0x wallet (the payTo you are about to pay)"),
  chain: z.string().max(64).optional().describe("CAIP-2 chain id; default eip155:8453 (Base)"),
  resource: z.string().max(2048).optional().describe("Optional resource URL or domain context"),
  known_recipients: z
    .array(address)
    .max(KNOWN_RECIPIENTS_MAX)
    .optional()
    .describe("Optional: up to 50 0x addresses you expect to pay; a lookalike of one returns caution"),
};

export const gateShape = {
  skill: z.unknown().optional().describe("One skill (string or object)"),
  skills: z.array(z.unknown()).optional().describe("Several skills"),
  mcp: z.unknown().optional().describe("An MCP server config"),
  content: z.string().optional().describe("Free-form content to scan"),
};

export const peerChallengeShape = {
  certificate: z.record(z.string(), z.unknown()).describe("The peer's CertBeforePay certificate"),
  min_score: z.number().int().min(0).max(100).optional(),
  require_tier: z.string().optional(),
};

type ToolResult = { content: { type: "text"; text: string }[]; isError?: boolean };

function result(status: number, body: unknown): ToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify({ http_status: status, body }) }],
    isError: status >= 400,
  };
}

function failure(err: unknown): ToolResult {
  const msg = err instanceof CbpError ? err.message : "cbp-guard: request failed";
  return { content: [{ type: "text", text: msg }], isError: true };
}

/** Build the MCP server around a CbpClient (tests pass a mocked one). */
export function createMcpServer(client: CbpClient): McpServer {
  const server = new McpServer({ name: "cbp-guard", version: VERSION });

  server.registerTool(
    "wallet_check",
    {
      description:
        "Check a destination wallet (x402 payTo) with CertBeforePay before paying: clear, caution (incl. address-poisoning lookalike) or block. Paid: $0.01 in USDC on Base via x402 from your key. Not an OFAC/sanctions screen.",
      inputSchema: walletCheckShape,
    },
    async (args) => {
      try {
        const r = await client.walletCheck({
          address: args.address,
          chain: args.chain,
          resource: args.resource,
          knownRecipients: args.known_recipients,
        });
        return result(r.status, r.body);
      } catch (err) {
        return failure(err);
      }
    },
  );

  server.registerTool(
    "gate",
    {
      description:
        "Scan a skill, skills, an MCP server config or content with CertBeforePay POST /v1/gate. Paid: $0.02 in USDC on Base via x402 from your key.",
      inputSchema: gateShape,
    },
    async (args) => {
      const body = Object.fromEntries(Object.entries(args).filter(([, v]) => v !== undefined));
      if (Object.keys(body).length === 0)
        return failure(new CbpError("invalid_input", "give skill, skills, mcp or content"));
      try {
        const r = await client.gate(body);
        return result(r.status, r.body);
      } catch (err) {
        return failure(err);
      }
    },
  );

  server.registerTool(
    "peer_challenge",
    {
      description:
        "Verify a peer's CertBeforePay certificate against a policy with POST /v1/peer/challenge. Paid: $0.01 in USDC on Base via x402 from your key.",
      inputSchema: peerChallengeShape,
    },
    async (args) => {
      const body = Object.fromEntries(Object.entries(args).filter(([, v]) => v !== undefined));
      try {
        const r = await client.peerChallenge(body);
        return result(r.status, r.body);
      } catch (err) {
        return failure(err);
      }
    },
  );
  return server;
}

/** Reads the caller's key from CBP_GUARD_PRIVATE_KEY and builds an x402 v2 payment client. */
export async function paymentClientFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<PaymentClientLike> {
  const key = (env[KEY_ENV] ?? "").trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(key)) {
    throw new Error(`cbp-guard: set ${KEY_ENV} to the private key (0x + 64 hex) of the wallet that pays for checks`);
  }
  let account: ReturnType<typeof import("viem/accounts").privateKeyToAccount>;
  const [{ x402Client }, { ExactEvmScheme, toClientEvmSigner }, { privateKeyToAccount }] = await Promise.all([
    import("@x402/core/client"),
    import("@x402/evm"),
    import("viem/accounts"),
  ]);
  try {
    account = privateKeyToAccount(key as `0x${string}`);
  } catch {
    // viem's message can include the rejected key (as a number); never pass it on.
    throw new Error(INVALID_KEY);
  }
  return new x402Client().register("eip155:8453", new ExactEvmScheme(toClientEvmSigner(account)));
}

/** Daily spend cap for the MCP server from CBP_GUARD_DAILY_BUDGET_USD (default $1.00; "Infinity" = no cap). */
export function budgetFromEnv(env: NodeJS.ProcessEnv = process.env, now?: () => number): SpendBudget {
  const raw = (env[BUDGET_ENV] ?? "").trim();
  const usd = raw === "" ? DEFAULT_DAILY_BUDGET_USD : Number(raw);
  if (Number.isNaN(usd) || usd < 0) {
    throw new Error(`cbp-guard: ${BUDGET_ENV} must be a number >= 0 (or Infinity for no cap)`);
  }
  return new SpendBudget(usd, now);
}

/** `cbp-guard mcp`: refuses to start without a key (every tool is paid). */
export async function runMcp(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const budget = budgetFromEnv(env);
  const paymentClient = await paymentClientFromEnv(env);
  const client = new CbpClient({ paymentClient, baseUrl: env[BASE_URL_ENV] || undefined, budget });
  const server = createMcpServer(client);
  await server.connect(new StdioServerTransport());
}
