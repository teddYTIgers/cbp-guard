/**
 * 0.1.2: `cbp-guard mcp` starts without CBP_GUARD_PRIVATE_KEY so directories (e.g. Glama) can list tools.
 * The payment client is built on the first tool call; a missing or invalid key returns an MCP error result
 * with no network call, no payment and no echo of the key. Test keys are throwaway (generatePrivateKey) or
 * obviously fake.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { generatePrivateKey } from "viem/accounts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BUDGET_ENV, KEY_ENV, runMcp } from "../src/mcp.js";
import { fakeCbp, SELLER, walletBody } from "./helpers.js";

const SET_KEY = `cbp-guard: set ${KEY_ENV} to the private key (0x + 64 hex) of the wallet that pays for checks`;
const NOT_VALID = `cbp-guard: ${KEY_ENV} is not a valid secp256k1 private key`;
const CALLS = [
  { name: "wallet_check", arguments: { address: SELLER } },
  { name: "gate", arguments: { content: "hello" } },
  { name: "peer_challenge", arguments: { certificate: { payload: {} } } },
];

let out = "";
let fetchSpy: ReturnType<typeof vi.fn>;

beforeEach(() => {
  out = "";
  const capture = (chunk: unknown) => {
    out += String(chunk);
    return true;
  };
  vi.spyOn(process.stdout, "write").mockImplementation(capture as never);
  vi.spyOn(process.stderr, "write").mockImplementation(capture as never);
  fetchSpy = vi.fn(async () => new Response(JSON.stringify(walletBody("clear")), { status: 200 }));
  vi.stubGlobal("fetch", fetchSpy);
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function start(env: NodeJS.ProcessEnv) {
  const [a, b] = InMemoryTransport.createLinkedPair();
  await runMcp(env, a);
  const client = new Client({ name: "directory", version: "0" });
  await client.connect(b);
  return client;
}

function text(res: unknown) {
  const r = res as { content: { text: string }[]; isError?: boolean };
  return { isError: r.isError, text: r.content[0].text };
}

describe("cbp-guard mcp without a key", () => {
  it("starts and lists wallet_check, gate and peer_challenge", async () => {
    const client = await start({});
    const names = (await client.listTools()).tools.map((t) => t.name).sort();
    expect(names).toEqual(["gate", "peer_challenge", "wallet_check"]);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("each paid tool returns the set-key error, with no network call", async () => {
    const client = await start({});
    for (const call of CALLS) {
      expect(text(await client.callTool(call))).toEqual({ isError: true, text: SET_KEY });
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("a malformed key gives the same error and is never echoed", async () => {
    const bogus = `0x${"c".repeat(63)}z`;
    const client = await start({ [KEY_ENV]: bogus });
    const res = await client.callTool(CALLS[0]);
    expect(text(res)).toEqual({ isError: true, text: SET_KEY });
    expect(JSON.stringify(res)).not.toContain("c".repeat(20));
    expect(out).not.toContain("c".repeat(20));
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("an out-of-range key gives the fixed not-valid error with no hex or decimal form of it", async () => {
    for (const key of [`0x${"0".repeat(64)}`, `0x${"f".repeat(64)}`]) {
      const client = await start({ [KEY_ENV]: key });
      const res = await client.callTool(CALLS[0]);
      expect(text(res)).toEqual({ isError: true, text: NOT_VALID });
      expect(JSON.stringify(res)).not.toMatch(/[0-9a-fA-F]{32,}|\d{20,}/);
    }
    expect(out).not.toMatch(/[0-9a-fA-F]{32,}|\d{20,}/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("input validation still runs first (an empty gate call is refused locally)", async () => {
    const client = await start({});
    const r = text(await client.callTool({ name: "gate", arguments: {} }));
    expect(r.isError).toBe(true);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("an invalid budget still refuses to start (fail fast), without a key too", async () => {
    await expect(start({ [BUDGET_ENV]: "lots" })).rejects.toThrow(BUDGET_ENV);
  });

  it("an http base URL still refuses to start, without a key too", async () => {
    await expect(start({ CBP_GUARD_BASE_URL: "http://evil.example" })).rejects.toThrow(/https/);
  });
});

describe("cbp-guard mcp with a throwaway key", () => {
  it("the paid path is unchanged: 402, signed with the key, verdict returned; the key never appears", async () => {
    const key = generatePrivateKey(); // random throwaway, never funded
    const cbp = fakeCbp(() => ({ status: 200, body: walletBody("clear") }));
    vi.stubGlobal("fetch", cbp.fetch);
    const client = await start({ [KEY_ENV]: key });
    const res = await client.callTool(CALLS[0]);
    expect(text(res)).toEqual({
      isError: false,
      text: JSON.stringify({ http_status: 200, body: walletBody("clear") }),
    });
    expect(cbp.calls.map((c) => c.path)).toEqual(["/v1/wallet/check", "/v1/wallet/check"]);
    expect("payment-signature" in cbp.calls[0].headers).toBe(false);
    expect("payment-signature" in cbp.calls[1].headers).toBe(true);
    expect(JSON.stringify(res)).not.toContain(key.slice(2));
    expect(out).not.toContain(key.slice(2));
  });
});
