/**
 * Sentinel fix round CBG1 (PR #1): budget reservation, MCP budget, protected publish environment,
 * body deadline + size cap, resource stripping, https + asset/network pin, no key material in output,
 * no dangling source maps. All HTTP is mocked.
 */
import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { PaymentPayload, PaymentRequired } from "@x402/core/types";
import { generatePrivateKey } from "viem/accounts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SpendBudget } from "../src/budget.js";
import { main, safeMessage } from "../src/cli.js";
import {
  CBP_PAYTO,
  CbpClient,
  CbpError,
  MAX_RESOURCE_LENGTH,
  MAX_RESPONSE_BYTES,
  sanitizeResource,
} from "../src/client.js";
import { type GuardDecision, withCbpGuard } from "../src/guard.js";
import { BUDGET_ENV, budgetFromEnv, createMcpServer, KEY_ENV, paymentClientFromEnv } from "../src/mcp.js";
import { fakeCbp, fakePaymentClient, paymentRequired, SELLER, USDC_BASE, walletBody } from "./helpers.js";

const read = (p: string) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");
const paidCalls = (calls: { headers: Record<string, string> }[]) =>
  calls.filter((c) => "payment-signature" in c.headers).length;
const addr = (i: number) => `0x${i.toString(16).padStart(40, "a")}`;

/** A fetch whose CBP 402 offers the given requirement fields; the paid retry answers clear. */
function custom402(over: Record<string, unknown>) {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const paid = new Headers(init?.headers).has("payment-signature");
    if (!paid) {
      const pr = paymentRequired({ payTo: CBP_PAYTO, ...over }, String(input));
      return new Response(JSON.stringify(pr), { status: 402 });
    }
    return new Response(JSON.stringify(walletBody("clear")), { status: 200 });
  }) as typeof fetch;
}

/** Headers arrive, then a body that never ends. */
function hangingBody(status = 200) {
  return new Response(new ReadableStream({ start() {} }), { status });
}

describe("CBG1-1 budget is reserved before signing and counts every signed payment", () => {
  it("150 parallel checks on distinct payTos never exceed the $1.00 default (exactly 100 paid)", async () => {
    const cbp = fakeCbp(() => ({ status: 200, body: walletBody("clear") }));
    const pay = fakePaymentClient();
    const guard = withCbpGuard(pay, { fetch: cbp.fetch, cacheTtlMs: 0 });
    const decisions = await Promise.all(Array.from({ length: 150 }, (_, i) => guard.decide({ payTo: addr(i) })));
    expect(paidCalls(cbp.calls)).toBe(100);
    expect(guard.budget.spentAtomic()).toBe(1_000_000n);
    expect(decisions.filter((d) => d.action === "allow")).toHaveLength(100);
    const refused = decisions.filter((d) => d.action === "block");
    expect(refused).toHaveLength(50);
    for (const d of refused) expect(d).toMatchObject({ verdict: "unavailable", detail: "daily_budget_reached" });
  });

  it("150 parallel hook calls through the x402 client also stay at 100 paid checks", async () => {
    const cbp = fakeCbp(() => ({ status: 200, body: walletBody("clear") }));
    const pay = fakePaymentClient();
    withCbpGuard(pay, { fetch: cbp.fetch, cacheTtlMs: 0 });
    const results = await Promise.allSettled(
      Array.from({ length: 150 }, (_, i) => pay.createPaymentPayload(paymentRequired({ payTo: addr(i) }))),
    );
    expect(paidCalls(cbp.calls)).toBe(100);
    expect(results.filter((r) => r.status === "rejected")).toHaveLength(50);
  });

  it("a signed check whose answer is malformed still counts", async () => {
    const cbp = fakeCbp(() => ({ status: 200, raw: "not json" }));
    const pay = fakePaymentClient();
    const seen: GuardDecision[] = [];
    const guard = withCbpGuard(pay, { fetch: cbp.fetch, dailyBudgetUsd: 0.02, onDecision: (d) => seen.push(d) });
    for (let i = 0; i < 5; i++) await guard.decide({ payTo: SELLER });
    expect(paidCalls(cbp.calls)).toBe(2);
    seen.splice(0, seen.length, ...seen.filter((d) => d.detail !== "cbp_payto"));
    expect(seen).toHaveLength(5);
    expect(seen.slice(0, 2).map((d) => d.detail)).toEqual(["malformed_body", "malformed_body"]);
    expect(seen.slice(2).every((d) => d.detail === "daily_budget_reached" && d.action === "block")).toBe(true);
  });

  it("a signed check whose paid answer times out still counts", async () => {
    let n = 0;
    const fetchImpl = (async (input: RequestInfo | URL) => {
      n++;
      if (n === 1) {
        const pr = paymentRequired({ payTo: CBP_PAYTO }, String(input));
        return new Response(JSON.stringify(pr), { status: 402 });
      }
      return hangingBody();
    }) as typeof fetch;
    const budget = new SpendBudget(0.01);
    const c = new CbpClient({ paymentClient: fakePaymentClient(), fetch: fetchImpl, timeoutMs: 50, budget });
    await expect(c.walletCheck({ address: SELLER })).rejects.toMatchObject({ code: "timeout" });
    expect(budget.spentAtomic()).toBe(10_000n);
    expect(budget.fits(1n)).toBe(false);
  });

  it("counts the real signed amount, not a fixed $0.01", async () => {
    const cbp = fakeCbp(() => ({ status: 200, body: walletBody("clear") }), { price: { "/v1/wallet/check": "30000" } });
    const pay = fakePaymentClient();
    const guard = withCbpGuard(pay, {
      fetch: cbp.fetch,
      cacheTtlMs: 0,
      dailyBudgetUsd: 0.05,
      maxPriceAtomic: { "/v1/wallet/check": 30_000n },
    });
    expect((await guard.decide({ payTo: SELLER })).action).toBe("allow");
    expect(guard.budget.spentAtomic()).toBe(30_000n);
    expect(await guard.decide({ payTo: SELLER })).toMatchObject({ action: "block", detail: "daily_budget_reached" });
    expect(paidCalls(cbp.calls)).toBe(1);
  });

  it("releases the reservation when nothing was signed", async () => {
    const cbp = fakeCbp(() => ({ status: 200, body: walletBody("clear") }));
    const budget = new SpendBudget(0.01);
    let fail = true;
    const pay = {
      async createPaymentPayload(pr: PaymentRequired): Promise<PaymentPayload> {
        if (fail) throw new Error("signer unavailable");
        return { x402Version: 2, resource: pr.resource, accepted: pr.accepts[0], payload: { signature: "0x01" } };
      },
    };
    const c = new CbpClient({ paymentClient: pay, fetch: cbp.fetch, budget });
    await expect(c.walletCheck({ address: SELLER })).rejects.toThrow("signer unavailable");
    expect(budget.spentAtomic()).toBe(0n);
    fail = false;
    expect((await c.walletCheck({ address: SELLER })).paid).toBe(true);
    expect(budget.spentAtomic()).toBe(10_000n);
  });

  it("the budget resets on the next UTC day", () => {
    let now = Date.UTC(2026, 10, 21, 23, 59);
    const b = new SpendBudget(0.01, () => now);
    const r = b.reserve(10_000n);
    expect(r).not.toBeNull();
    expect(b.reserve(1n)).toBeNull();
    now += 2 * 60_000;
    expect(b.spentAtomic()).toBe(0n);
    if (r) b.release(r); // yesterday's reservation does not touch today's spend
    expect(b.reserve(10_000n)).not.toBeNull();
  });
});

describe("CBG1-2 MCP server daily budget (CBP_GUARD_DAILY_BUDGET_USD)", () => {
  async function connect(budget: SpendBudget) {
    const cbp = fakeCbp((path) => ({ status: 200, body: path === "/v1/wallet/check" ? walletBody("clear") : {} }));
    const pay = fakePaymentClient();
    const server = createMcpServer(new CbpClient({ paymentClient: pay, fetch: cbp.fetch, budget }));
    const [a, b] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "test", version: "0" });
    await Promise.all([server.connect(a), client.connect(b)]);
    return { client, cbp, pay };
  }

  it("defaults to $1.00, accepts overrides and Infinity, rejects junk", () => {
    expect(budgetFromEnv({}).capAtomic).toBe(1_000_000n);
    expect(budgetFromEnv({ [BUDGET_ENV]: "" }).capAtomic).toBe(1_000_000n);
    expect(budgetFromEnv({ [BUDGET_ENV]: "0.25" }).capAtomic).toBe(250_000n);
    expect(budgetFromEnv({ [BUDGET_ENV]: "Infinity" }).capAtomic).toBeNull();
    for (const bad of ["abc", "-1", "NaN"]) expect(() => budgetFromEnv({ [BUDGET_ENV]: bad })).toThrow(BUDGET_ENV);
  });

  it("refuses tool calls once the cap is used up; nothing more is signed", async () => {
    const { client, cbp, pay } = await connect(budgetFromEnv({ [BUDGET_ENV]: "0.03" }));
    const call = async (name: string, args: Record<string, unknown>) =>
      (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: { text: string }[] };
    expect((await call("gate", { content: "hi" })).isError).toBe(false);
    expect((await call("wallet_check", { address: SELLER })).isError).toBe(false);
    const third = await call("gate", { content: "again" });
    expect(third.isError).toBe(true);
    expect(third.content[0].text).toContain("budget_exhausted");
    expect(pay.signed).toHaveLength(2);
    expect(paidCalls(cbp.calls)).toBe(2);
  });

  it("parallel MCP tool calls never exceed the cap", async () => {
    const { client, pay } = await connect(budgetFromEnv({ [BUDGET_ENV]: "0.05" }));
    const res = (await Promise.all(
      Array.from({ length: 20 }, () => client.callTool({ name: "wallet_check", arguments: { address: SELLER } })),
    )) as { isError?: boolean }[];
    expect(pay.signed).toHaveLength(5);
    expect(res.filter((r) => r.isError)).toHaveLength(15);
  });
});

describe("CBG1-3 publishing needs the protected environment", () => {
  it("publish job uses environment npm-publish and the README makes it a required step", () => {
    const wf = read(".github/workflows/publish.yml");
    expect(wf).toMatch(/^\s+environment: npm-publish\s*$/m);
    const readme = read("README.md");
    expect(readme).toContain("**Required, before step 3:**");
    expect(readme).toContain("required reviewer `teddYTIgers`");
    expect(readme).toContain("only tags matching `v*.*.*`");
    expect(readme).not.toMatch(/Optionally add a required reviewer/);
  });
});

describe("CBG1-4 one deadline covers the body; body size is capped", () => {
  it("headers then a never-ending body -> timeout -> block (failMode default)", async () => {
    const fetchImpl = (async () => hangingBody()) as unknown as typeof fetch;
    const pay = fakePaymentClient();
    const guard = withCbpGuard(pay, { fetch: fetchImpl, timeoutMs: 50 });
    const t0 = Date.now();
    const d = await guard.decide({ payTo: SELLER });
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(d).toMatchObject({ action: "block", verdict: "unavailable", detail: "timeout" });
    expect(pay.signed).toHaveLength(0);
  });

  it("failMode allow lets the payment through on a body timeout", async () => {
    const fetchImpl = (async () => hangingBody()) as unknown as typeof fetch;
    const guard = withCbpGuard(fakePaymentClient(), { fetch: fetchImpl, timeoutMs: 50, failMode: "allow" });
    expect(await guard.decide({ payTo: SELLER })).toMatchObject({ action: "allow", detail: "timeout" });
  });

  it("an answer over 64 KB is malformed_body -> block, streamed or declared", async () => {
    const big = `{"ok":true,"verdict":"clear","pad":"${"x".repeat(MAX_RESPONSE_BYTES)}"}`;
    const cbp = fakeCbp(() => ({ status: 200, raw: big }));
    const g1 = withCbpGuard(fakePaymentClient(), { fetch: cbp.fetch });
    expect(await g1.decide({ payTo: SELLER })).toMatchObject({ action: "block", detail: "malformed_body" });

    // Declared too big: refused from the header alone (the body never ends, so reading it would time out).
    const declared = (async () =>
      new Response(new ReadableStream({ start() {} }), {
        status: 200,
        headers: { "content-length": String(MAX_RESPONSE_BYTES + 1) },
      })) as unknown as typeof fetch;
    const g2 = withCbpGuard(fakePaymentClient(), { fetch: declared, timeoutMs: 2000 });
    expect(await g2.decide({ payTo: SELLER })).toMatchObject({ action: "block", detail: "malformed_body" });
  });

  it("an answer just under the cap is read normally", async () => {
    const body = JSON.stringify(walletBody("clear", { pad: "x".repeat(MAX_RESPONSE_BYTES - 200) }));
    const cbp = fakeCbp(() => ({ status: 200, raw: body }));
    const g = withCbpGuard(fakePaymentClient(), { fetch: cbp.fetch });
    expect((await g.decide({ payTo: SELLER })).action).toBe("allow");
  });
});

describe("CBG1-5 resource URL: query string and fragment are never sent", () => {
  it("the hook sends origin + path only", async () => {
    const cbp = fakeCbp(() => ({ status: 200, body: walletBody("clear") }));
    const pay = fakePaymentClient();
    withCbpGuard(pay, { fetch: cbp.fetch });
    await pay.createPaymentPayload(
      paymentRequired({}, "https://user:pw@seller.example/paid/item?token=SECRET123&u=me#frag"),
    );
    const sent = cbp.calls.map((c) => c.body.resource);
    expect(sent.every((r) => r === "https://seller.example/paid/item")).toBe(true);
    expect(JSON.stringify(cbp.calls)).not.toMatch(/SECRET123|token=|frag|user:pw/);
  });

  it("sanitizeResource: long URLs fall back to the origin, other schemes are dropped, domains pass", () => {
    expect(sanitizeResource(`https://seller.example/${"a".repeat(MAX_RESOURCE_LENGTH)}?q=1`)).toBe(
      "https://seller.example",
    );
    expect(sanitizeResource("http://localhost:3000/x?y=1#z")).toBe("http://localhost:3000/x");
    expect(sanitizeResource("javascript:alert(1)")).toBeUndefined();
    expect(sanitizeResource("data:text/plain,hello")).toBeUndefined();
    expect(sanitizeResource("seller.example")).toBe("seller.example");
    expect(sanitizeResource("x".repeat(MAX_RESOURCE_LENGTH + 1))).toBeUndefined();
    expect(sanitizeResource(undefined)).toBeUndefined();
  });
});

describe("CBG1-6 https base URL; CertBeforePay 402 pinned to USDC on Base", () => {
  it("rejects plain http for non-local hosts; allows https, localhost and the explicit test flag", () => {
    const paymentClient = fakePaymentClient();
    for (const bad of ["http://evil.example", "http://certbeforepay.com", "ftp://x.example", "not a url"]) {
      expect(() => new CbpClient({ paymentClient, baseUrl: bad })).toThrow(/invalid_input/);
      expect(() => withCbpGuard(fakePaymentClient(), { baseUrl: bad })).toThrow(/invalid_input/);
    }
    for (const ok of ["https://certbeforepay.com/", "http://localhost:8080", "http://127.0.0.1:9", "http://[::1]:9"]) {
      expect(() => new CbpClient({ paymentClient, baseUrl: ok })).not.toThrow();
    }
    expect(() => new CbpClient({ paymentClient, baseUrl: "http://cbp.test", allowInsecureHttp: true })).not.toThrow();
  });

  it("the MCP server refuses an http base URL from the environment", async () => {
    const { runMcp } = await import("../src/mcp.js");
    await expect(
      runMcp({ [KEY_ENV]: generatePrivateKey(), CBP_GUARD_BASE_URL: "http://evil.example" }),
    ).rejects.toThrow(/https/);
  });

  it("a 402 on another network or asset is refused and nothing is signed", async () => {
    for (const [over, code] of [
      [{ network: "eip155:84532" }, "network_mismatch"],
      [{ network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" }, "network_mismatch"],
      [{ asset: `0x${"4".repeat(40)}` }, "asset_mismatch"],
      [{ asset: undefined }, "asset_mismatch"],
    ] as const) {
      const pay = fakePaymentClient();
      const c = new CbpClient({ paymentClient: pay, fetch: custom402(over) });
      await expect(c.walletCheck({ address: SELLER })).rejects.toMatchObject({ code });
      expect(pay.signed).toHaveLength(0);
      const g = withCbpGuard(fakePaymentClient(), { fetch: custom402(over) });
      expect(await g.decide({ payTo: SELLER })).toMatchObject({ action: "block", detail: code });
    }
  });

  it("USDC on Base is accepted in any letter case", async () => {
    const pay = fakePaymentClient();
    const c = new CbpClient({
      paymentClient: pay,
      fetch: custom402({ asset: USDC_BASE.toUpperCase().replace("0X", "0x") }),
    });
    expect((await c.walletCheck({ address: SELLER })).paid).toBe(true);
  });
});

describe("CBG1-7 no key material in any output", () => {
  let out = "";
  beforeEach(() => {
    out = "";
    const capture = (chunk: unknown) => {
      out += String(chunk);
      return true;
    };
    vi.spyOn(process.stdout, "write").mockImplementation(capture as never);
    vi.spyOn(process.stderr, "write").mockImplementation(capture as never);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env[KEY_ENV];
    delete process.env[BUDGET_ENV];
  });

  const outOfRange = [`0x${"0".repeat(64)}`, `0x${"f".repeat(64)}`];

  it("out-of-range keys get a fixed message (no hex, no decimal form of the key)", async () => {
    for (const key of outOfRange) {
      const err = await paymentClientFromEnv({ [KEY_ENV]: key }).catch((e) => e);
      expect(err.message).toBe(`cbp-guard: ${KEY_ENV} is not a valid secp256k1 private key`);
      process.env[KEY_ENV] = key;
      out = "";
      expect(await main(["mcp"])).toBe(1);
      expect(out.trim()).toBe(`cbp-guard: ${KEY_ENV} is not a valid secp256k1 private key`);
      expect(out).not.toMatch(/[0-9a-fA-F]{32,}|\d{20,}/);
    }
  });

  it("an invalid budget with a valid key refuses to start without printing the key", async () => {
    const key = generatePrivateKey();
    process.env[KEY_ENV] = key;
    process.env[BUDGET_ENV] = "lots";
    expect(await main(["mcp"])).toBe(1);
    expect(out).toContain(BUDGET_ENV);
    expect(out).not.toContain(key.slice(2));
    expect(out).not.toMatch(/[0-9a-fA-F]{32,}/);
  });

  it("safeMessage drops foreign messages and anything that looks like key material", () => {
    expect(safeMessage(new Error("cbp-guard: nice"))).toBe("cbp-guard: nice");
    expect(safeMessage(new Error("boom from a dependency"))).toBe("cbp-guard: failed to start");
    expect(safeMessage(new Error(`cbp-guard: ${"ab".repeat(20)}`))).toBe("cbp-guard: failed to start");
    expect(safeMessage(new Error(`cbp-guard: got ${"9".repeat(30)}`))).toBe("cbp-guard: failed to start");
    expect(safeMessage("x")).toBe("cbp-guard: failed to start");
  });

  it("MCP tool results and errors never contain the key", async () => {
    const key = generatePrivateKey();
    const real = await paymentClientFromEnv({ [KEY_ENV]: key });
    for (const handler of [
      () => ({ status: 200, body: walletBody("clear") }),
      () => ({ status: 503, body: { error: "stale" } }),
      () => ({ status: 200, raw: "nope" }),
    ]) {
      const cbp = fakeCbp(handler);
      const server = createMcpServer(
        new CbpClient({ paymentClient: real, fetch: cbp.fetch, budget: new SpendBudget(1) }),
      );
      const [a, b] = InMemoryTransport.createLinkedPair();
      const client = new Client({ name: "t", version: "0" });
      await Promise.all([server.connect(a), client.connect(b)]);
      const res = await client.callTool({ name: "wallet_check", arguments: { address: SELLER } });
      expect(JSON.stringify(res)).not.toContain(key.slice(2));
    }
    expect(out).not.toContain(key.slice(2));
  });

  it("CbpError messages never carry key-like values", () => {
    expect(new CbpError("budget_exhausted", "daily budget reached; nothing signed").message).toBe(
      "cbp-guard: budget_exhausted: daily budget reached; nothing signed",
    );
  });
});

describe("CBG1-9 no dangling source maps in the package", () => {
  it("the build emits no source or declaration maps", () => {
    const build = JSON.parse(read("tsconfig.build.json"));
    expect(build.compilerOptions.sourceMap).toBe(false);
    expect(build.compilerOptions.declarationMap).toBe(false);
  });
});
