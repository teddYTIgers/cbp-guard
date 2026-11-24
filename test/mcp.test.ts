import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import { CbpClient } from "../src/client.js";
import { createMcpServer, KEY_ENV, paymentClientFromEnv } from "../src/mcp.js";
import { fakeCbp, fakePaymentClient, KNOWN, LOOKALIKE, LOOKALIKE_BODY, SELLER, walletBody } from "./helpers.js";

async function connect(handler: Parameters<typeof fakeCbp>[0]) {
  const cbp = fakeCbp(handler);
  const server = createMcpServer(new CbpClient({ paymentClient: fakePaymentClient(), fetch: cbp.fetch }));
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  return { client, cbp };
}

function parse(res: unknown) {
  const r = res as { content: { text: string }[]; isError?: boolean };
  return { isError: r.isError, text: r.content[0].text };
}

describe("stdio MCP server tools", () => {
  it("lists wallet_check, gate and peer_challenge", async () => {
    const { client } = await connect(() => ({ status: 200 }));
    const names = (await client.listTools()).tools.map((t) => t.name).sort();
    expect(names).toEqual(["gate", "peer_challenge", "wallet_check"]);
    const wc = (await client.listTools()).tools.find((t) => t.name === "wallet_check");
    expect(Object.keys((wc as { inputSchema: { properties: object } }).inputSchema.properties).sort()).toEqual([
      "address",
      "chain",
      "known_recipients",
      "resource",
    ]);
  });

  it("peer_challenge describes every input, when to use it and what it returns (0.1.3)", async () => {
    const { client } = await connect(() => ({ status: 200 }));
    const pc = (await client.listTools()).tools.find((t) => t.name === "peer_challenge") as {
      description: string;
      inputSchema: { properties: Record<string, { description?: string; minimum?: number; maximum?: number }> };
    };
    const props = pc.inputSchema.properties;
    expect(Object.keys(props).sort()).toEqual(["certificate", "min_score", "require_tier"]);
    for (const k of Object.keys(props)) expect(props[k].description, k).toBeTruthy();
    expect(props.min_score.description).toContain("default 60");
    expect([props.min_score.minimum, props.min_score.maximum]).toEqual([0, 100]);
    expect(props.require_tier.description).toContain("provisional, attested or endorsed");
    expect(pc.description).toContain("before you trust or pay it");
    expect(pc.description).toContain("ACCEPT");
    expect(pc.description).toContain("REJECT");
    expect(pc.description).toContain("Paid: $0.01 in USDC on Base via x402 from your key.");
  });

  it("wallet_check returns the mocked verdict and forwards known_recipients", async () => {
    const { client, cbp } = await connect(() => ({ status: 200, body: LOOKALIKE_BODY }));
    const r = parse(
      await client.callTool({ name: "wallet_check", arguments: { address: LOOKALIKE, known_recipients: [KNOWN] } }),
    );
    expect(r.isError).toBe(false);
    expect(JSON.parse(r.text)).toEqual({ http_status: 200, body: LOOKALIKE_BODY });
    expect(cbp.calls[1].body).toEqual({ address: LOOKALIKE, known_recipients: [KNOWN.toLowerCase()] });
  });

  it("wallet_check validates input (bad address, >50 recipients) without calling CertBeforePay", async () => {
    const { client, cbp } = await connect(() => ({ status: 200, body: walletBody("clear") }));
    for (const args of [
      { address: "0x12" },
      { address: SELLER, known_recipients: Array.from({ length: 51 }, () => KNOWN) },
      { address: SELLER, known_recipients: ["bad"] },
    ]) {
      const r = (await client.callTool({ name: "wallet_check", arguments: args })) as { isError?: boolean };
      expect(r.isError).toBe(true);
    }
    expect(cbp.calls).toHaveLength(0);
  });

  it("gate returns the mocked body; an empty call is refused", async () => {
    const { client, cbp } = await connect((path, body) => ({
      status: 200,
      body: { path, echo: body, verdict: "PASS" },
    }));
    const r = parse(await client.callTool({ name: "gate", arguments: { content: "hello" } }));
    expect(JSON.parse(r.text).body).toEqual({ path: "/v1/gate", echo: { content: "hello" }, verdict: "PASS" });
    const empty = parse(await client.callTool({ name: "gate", arguments: {} }));
    expect(empty.isError).toBe(true);
    expect(cbp.calls.filter((c) => c.path === "/v1/gate")).toHaveLength(2);
  });

  it("peer_challenge returns the mocked body and validates min_score", async () => {
    const { client } = await connect(() => ({ status: 200, body: { decision: "ACCEPT" } }));
    const r = parse(
      await client.callTool({ name: "peer_challenge", arguments: { certificate: { payload: {} }, min_score: 80 } }),
    );
    expect(JSON.parse(r.text)).toEqual({ http_status: 200, body: { decision: "ACCEPT" } });
    const bad = (await client.callTool({ name: "peer_challenge", arguments: { certificate: {}, min_score: 101 } })) as {
      isError?: boolean;
    };
    expect(bad.isError).toBe(true);
  });

  it("an upstream 503 is returned as an error result", async () => {
    const { client } = await connect(() => ({ status: 503, body: { error: "scam_denylist_stale", charged: false } }));
    const r = parse(await client.callTool({ name: "wallet_check", arguments: { address: SELLER } }));
    expect(r.isError).toBe(true);
    expect(JSON.parse(r.text).http_status).toBe(503);
  });
});

describe("key from CBP_GUARD_PRIVATE_KEY only", () => {
  it("refuses to build a payment client without a valid key, and the error never echoes the value", async () => {
    await expect(paymentClientFromEnv({})).rejects.toThrow(KEY_ENV);
    const bogus = "0xnot-a-key-but-secret-looking-value";
    const err = await paymentClientFromEnv({ [KEY_ENV]: bogus }).catch((e) => e);
    expect(String(err.message)).not.toContain(bogus);
  });

  it("builds an x402 client from a throwaway test key", async () => {
    const { generatePrivateKey } = await import("viem/accounts");
    const c = await paymentClientFromEnv({ [KEY_ENV]: generatePrivateKey() });
    expect(typeof c.createPaymentPayload).toBe("function");
  });
});
