import { x402Client } from "@x402/core/client";
import { encodePaymentRequiredHeader } from "@x402/core/http";
import { ExactEvmScheme, toClientEvmSigner } from "@x402/evm";
import { wrapFetchWithPayment } from "@x402/fetch";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";
import { CBP_PAYTO } from "../src/client.js";
import { type CbpGuard, CbpGuardError, type GuardDecision, withCbpGuard } from "../src/guard.js";
import {
  fakeCbp,
  fakePaymentClient,
  KNOWN,
  LOOKALIKE,
  LOOKALIKE_BODY,
  paymentRequired,
  SCAM,
  SELLER,
  walletBody,
} from "./helpers.js";

function setup(
  verdictBody: unknown | ((body: Record<string, unknown>) => { status: number; body?: unknown; raw?: string }),
  guardOpts: ConstructorParameters<typeof CbpGuard>[1] = {},
  cbpOpts: Parameters<typeof fakeCbp>[1] = {},
) {
  const cbp = fakeCbp((_path, body) => {
    if (typeof verdictBody === "function")
      return (verdictBody as (b: Record<string, unknown>) => { status: number })(body);
    return { status: 200, body: verdictBody };
  }, cbpOpts);
  const pay = fakePaymentClient();
  const decisions: GuardDecision[] = [];
  const guard = withCbpGuard(pay, { fetch: cbp.fetch, onDecision: (d) => decisions.push(d), ...guardOpts });
  const sellerSigned = () =>
    pay.signed.filter(
      (pr) => pr.accepts[0].payTo === SELLER || pr.accepts[0].payTo === LOOKALIKE || pr.accepts[0].payTo === SCAM,
    );
  return { cbp, pay, guard, decisions, sellerSigned };
}

describe("hook verdicts (defaults are fail-closed)", () => {
  it("block refuses and nothing is signed for the seller", async () => {
    const s = setup(walletBody("block", { reasons: ["address_listed:scam"] }));
    await expect(s.pay.createPaymentPayload(paymentRequired({ payTo: SCAM }))).rejects.toThrow(
      "cbp-guard: block (address_listed:scam)",
    );
    expect(s.sellerSigned()).toHaveLength(0);
    expect(s.decisions.at(-1)?.verdict).toBe("block");
  });

  it("caution blocks by default", async () => {
    const s = setup(walletBody("caution"));
    await expect(s.pay.createPaymentPayload(paymentRequired())).rejects.toBeInstanceOf(CbpGuardError);
    expect(s.sellerSigned()).toHaveLength(0);
  });

  it("caution allowed with onCaution: allow", async () => {
    const s = setup(walletBody("caution"), { onCaution: "allow" });
    await s.pay.createPaymentPayload(paymentRequired());
    expect(s.sellerSigned()).toHaveLength(1);
  });

  it("onCaution: ask uses the callback; missing or throwing callback blocks", async () => {
    const yes = setup(walletBody("caution"), { onCaution: "ask", ask: async () => true });
    await yes.pay.createPaymentPayload(paymentRequired());
    expect(yes.sellerSigned()).toHaveLength(1);
    const no = setup(walletBody("caution"), { onCaution: "ask", ask: () => false });
    await expect(no.pay.createPaymentPayload(paymentRequired())).rejects.toThrow(/cbp-guard: block/);
    const missing = setup(walletBody("caution"), { onCaution: "ask" });
    await expect(missing.pay.createPaymentPayload(paymentRequired())).rejects.toThrow(/cbp-guard: block/);
    const throws = setup(walletBody("caution"), {
      onCaution: "ask",
      ask: () => {
        throw new Error("x");
      },
    });
    await expect(throws.pay.createPaymentPayload(paymentRequired())).rejects.toThrow(/cbp-guard: block/);
  });

  it("clear allows", async () => {
    const s = setup(walletBody("clear"));
    await s.pay.createPaymentPayload(paymentRequired());
    expect(s.sellerSigned()).toHaveLength(1);
    expect(s.decisions.at(-1)).toMatchObject({ action: "allow", verdict: "clear" });
  });

  it("block is never overridden by onCaution or failMode allow", async () => {
    const s = setup(walletBody("block"), { onCaution: "allow", failMode: "allow" });
    await expect(s.pay.createPaymentPayload(paymentRequired({ payTo: SCAM }))).rejects.toThrow(/cbp-guard: block/);
  });

  it("lookalike caution is a caution: blocked by default with matched address, label and note", async () => {
    const s = setup(LOOKALIKE_BODY);
    const err = await s.pay.createPaymentPayload(paymentRequired({ payTo: LOOKALIKE })).catch((e) => e);
    expect(err).toBeInstanceOf(CbpGuardError);
    expect(err.message).toBe("cbp-guard: block (address_poisoning_lookalike)");
    expect(err.decision.verdict).toBe("caution");
    expect(err.decision.lookalike).toEqual({
      matched_address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
      label: "USDC on Base",
      note: expect.stringContaining("address-poisoning trick"),
    });
    const allow = setup(LOOKALIKE_BODY, { onCaution: "allow" });
    await allow.pay.createPaymentPayload(paymentRequired({ payTo: LOOKALIKE }));
    expect(allow.sellerSigned()).toHaveLength(1);
  });
});

describe("no usable answer -> failMode (default block)", () => {
  const cases: [string, Parameters<typeof setup>[0], Parameters<typeof fakeCbp>[1]][] = [
    ["503 stale", () => ({ status: 503, body: { error: "scam_denylist_stale", charged: false } }), {}],
    ["503 misconfigured", () => ({ status: 503, body: { error: "provider_misconfigured" } }), {}],
    ["400", () => ({ status: 400, body: { error: "invalid_address" } }), {}],
    ["malformed JSON", () => ({ status: 200, raw: "<html>" }), {}],
    ["ok:false body", () => ({ status: 200, body: { ok: false, verdict: "clear" } }), {}],
    ["unknown verdict", () => ({ status: 200, body: { ok: true, verdict: "maybe" } }), {}],
    ["still 402 after paying", () => ({ status: 402, body: {} }), {}],
    ["network down", walletBody("clear"), { fail: "network" }],
    ["402 payTo not CertBeforePay", walletBody("clear"), { payTo: SCAM }],
    ["402 price above $0.01", walletBody("clear"), { price: { "/v1/wallet/check": "50000" } }],
  ];
  for (const [name, body, cbpOpts] of cases) {
    it(`${name}: blocks by default, allows with failMode allow`, async () => {
      const s = setup(body, {}, cbpOpts);
      const err = await s.pay.createPaymentPayload(paymentRequired()).catch((e) => e);
      expect(err).toBeInstanceOf(CbpGuardError);
      expect(err.decision.verdict).toBe("unavailable");
      expect(s.sellerSigned()).toHaveLength(0);
      const a = setup(body, { failMode: "allow" }, cbpOpts);
      await a.pay.createPaymentPayload(paymentRequired());
      expect(a.sellerSigned()).toHaveLength(1);
    });
  }

  it("timeout blocks by default", async () => {
    const s = setup(walletBody("clear"), { timeoutMs: 20 }, { fail: "hang" });
    const err = await s.pay.createPaymentPayload(paymentRequired()).catch((e) => e);
    expect(err.decision).toMatchObject({ verdict: "unavailable", detail: "timeout" });
  });

  it("price above max signs nothing for CertBeforePay either", async () => {
    const s = setup(walletBody("clear"), {}, { price: { "/v1/wallet/check": "50000" } });
    await s.pay.createPaymentPayload(paymentRequired()).catch(() => undefined);
    expect(s.pay.signed).toHaveLength(0);
  });
});

describe("known_recipients", () => {
  it("is forwarded (validated, lowercased, deduped) on the hook's wallet check", async () => {
    const s = setup(walletBody("clear"), { knownRecipients: [KNOWN, KNOWN.toUpperCase().replace("0X", "0x")] });
    await s.pay.createPaymentPayload(paymentRequired());
    const paid = s.cbp.calls.filter((c) => c.path === "/v1/wallet/check");
    expect(paid.length).toBe(2);
    for (const c of paid)
      expect(c.body).toEqual({
        address: SELLER,
        chain: "eip155:8453",
        resource: "https://seller.example/paid",
        known_recipients: [KNOWN.toLowerCase()],
      });
  });

  it("accepts a function and omits the field when empty", async () => {
    const s = setup(walletBody("clear"), { knownRecipients: async () => [] });
    await s.pay.createPaymentPayload(paymentRequired());
    expect(s.cbp.calls[0].body).not.toHaveProperty("known_recipients");
  });

  it("invalid list (51 entries or bad address) fails closed without calling CertBeforePay", async () => {
    const many = Array.from({ length: 51 }, (_, i) => `0x${i.toString(16).padStart(40, "0")}`);
    for (const list of [many, ["0x12"]]) {
      const s = setup(walletBody("clear"), { knownRecipients: list });
      const err = await s.pay.createPaymentPayload(paymentRequired()).catch((e) => e);
      expect(err.decision).toMatchObject({ verdict: "unavailable", detail: "invalid_known_recipients" });
      expect(s.cbp.calls).toHaveLength(0);
    }
  });
});

describe("skip, budget, minimum, cache", () => {
  it("skips the check when payTo is CertBeforePay's own payTo (any case)", async () => {
    const s = setup(walletBody("block"));
    for (const p of [CBP_PAYTO, CBP_PAYTO.toUpperCase().replace("0X", "0x")]) {
      await s.pay.createPaymentPayload(paymentRequired({ payTo: p }));
    }
    expect(s.cbp.calls).toHaveLength(0);
    expect(s.pay.signed).toHaveLength(2);
    expect(s.decisions.every((d) => d.action === "skip" && d.detail === "cbp_payto")).toBe(true);
  });

  it("the CertBeforePay check payment itself goes through the guarded client without recursion", async () => {
    const s = setup(walletBody("clear"));
    await s.pay.createPaymentPayload(paymentRequired());
    expect(s.pay.signed.map((p) => p.accepts[0].payTo)).toEqual([CBP_PAYTO, SELLER]);
  });

  it("invalid payTo blocks", async () => {
    const s = setup(walletBody("clear"));
    await expect(s.pay.createPaymentPayload(paymentRequired({ payTo: "0xnope" }))).rejects.toThrow(
      "cbp-guard: block (invalid_payto)",
    );
  });

  it("minAmountUsd skips tiny USDC payments only", async () => {
    const s = setup(walletBody("block"), { minAmountUsd: 0.05 });
    await s.pay.createPaymentPayload(paymentRequired({ amount: "10000" }));
    expect(s.cbp.calls).toHaveLength(0);
    await expect(s.pay.createPaymentPayload(paymentRequired({ amount: "100000" }))).rejects.toThrow(/block/);
    await expect(
      s.pay.createPaymentPayload(paymentRequired({ amount: "1", asset: `0x${"9".repeat(40)}` })),
    ).rejects.toThrow(/block/);
  });

  it("dailyBudgetUsd caps paid checks, then failMode applies; resets next UTC day", async () => {
    let now = Date.UTC(2026, 10, 21, 12);
    const s = setup(walletBody("clear"), { dailyBudgetUsd: 0.02, cacheTtlMs: 0, now: () => now });
    await s.pay.createPaymentPayload(paymentRequired());
    await s.pay.createPaymentPayload(paymentRequired());
    const err = await s.pay.createPaymentPayload(paymentRequired()).catch((e) => e);
    expect(err.decision).toMatchObject({ verdict: "unavailable", detail: "daily_budget_reached" });
    now += 24 * 3600_000;
    await s.pay.createPaymentPayload(paymentRequired());
  });

  it("caches real verdicts for a short TTL, never past it", async () => {
    let now = 1_000_000;
    const s = setup(walletBody("clear"), { now: () => now });
    await s.pay.createPaymentPayload(paymentRequired());
    await s.pay.createPaymentPayload(paymentRequired());
    expect(s.cbp.calls.filter((c) => "payment-signature" in c.headers)).toHaveLength(1);
    expect(s.decisions.at(-1)?.cached).toBe(true);
    now += 5 * 60_000;
    await s.pay.createPaymentPayload(paymentRequired());
    expect(s.cbp.calls.filter((c) => "payment-signature" in c.headers)).toHaveLength(2);
  });

  it("TTL is clamped to 15 minutes", async () => {
    let now = 0;
    const s = setup(walletBody("clear"), { cacheTtlMs: 24 * 3600_000, now: () => now });
    await s.pay.createPaymentPayload(paymentRequired());
    now += 15 * 60_000;
    await s.pay.createPaymentPayload(paymentRequired());
    expect(s.cbp.calls.filter((c) => "payment-signature" in c.headers)).toHaveLength(2);
  });

  it("does not cache 503 operator failures", async () => {
    let n = 0;
    const s = setup(() =>
      n++ === 0 ? { status: 503, body: { error: "scam_denylist_stale" } } : { status: 200, body: walletBody("clear") },
    );
    await expect(s.pay.createPaymentPayload(paymentRequired())).rejects.toThrow(/block/);
    await s.pay.createPaymentPayload(paymentRequired());
    expect(s.sellerSigned()).toHaveLength(1);
  });

  it("cache key includes known_recipients", async () => {
    let list = [KNOWN];
    const s = setup(walletBody("clear"), { knownRecipients: () => list });
    await s.pay.createPaymentPayload(paymentRequired());
    list = [];
    await s.pay.createPaymentPayload(paymentRequired());
    expect(s.cbp.calls.filter((c) => "payment-signature" in c.headers)).toHaveLength(2);
  });
});

describe("with the real x402 v2 client (@x402/core, @x402/evm, @x402/fetch), all HTTP mocked", () => {
  function realClient() {
    const account = privateKeyToAccount(generatePrivateKey()); // throwaway test key, never funded
    const scheme = new ExactEvmScheme(toClientEvmSigner(account));
    const spy = vi.spyOn(scheme, "createPaymentPayload");
    const client = new x402Client().register("eip155:8453", scheme);
    return { client, spy };
  }

  it("block: the scheme never signs the seller payment", async () => {
    const { client, spy } = realClient();
    const cbp = fakeCbp(() => ({ status: 200, body: walletBody("block", { reasons: ["address_listed:x"] }) }));
    withCbpGuard(client, { fetch: cbp.fetch });
    await expect(client.createPaymentPayload(paymentRequired({ payTo: SCAM }))).rejects.toThrow(
      "cbp-guard: block (address_listed:x)",
    );
    const sellerCalls = spy.mock.calls.filter((c) => (c[1] as { payTo: string }).payTo === SCAM);
    expect(sellerCalls).toHaveLength(0);
    expect(spy.mock.calls.filter((c) => (c[1] as { payTo: string }).payTo === CBP_PAYTO)).toHaveLength(1);
  });

  it("clear: wrapFetchWithPayment pays the seller after the check", async () => {
    const { client } = realClient();
    const cbp = fakeCbp(() => ({ status: 200, body: walletBody("clear") }));
    withCbpGuard(client, { fetch: cbp.fetch });
    const seller = async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = new Request(input, init);
      if (req.headers.get("payment-signature")) return new Response(JSON.stringify({ data: 1 }), { status: 200 });
      return new Response("{}", {
        status: 402,
        headers: { "PAYMENT-REQUIRED": encodePaymentRequiredHeader(paymentRequired()) },
      });
    };
    const res = await wrapFetchWithPayment(seller as typeof fetch, client)("https://seller.example/paid");
    expect(res.status).toBe(200);
    expect(cbp.calls.map((c) => c.path)).toEqual(["/v1/wallet/check", "/v1/wallet/check"]);
  });

  it("block through wrapFetchWithPayment surfaces the cbp-guard reason", async () => {
    const { client } = realClient();
    const cbp = fakeCbp(() => ({ status: 200, body: LOOKALIKE_BODY }));
    withCbpGuard(client, { fetch: cbp.fetch });
    const seller = async () =>
      new Response("{}", {
        status: 402,
        headers: { "PAYMENT-REQUIRED": encodePaymentRequiredHeader(paymentRequired({ payTo: LOOKALIKE })) },
      });
    await expect(wrapFetchWithPayment(seller as typeof fetch, client)("https://seller.example/paid")).rejects.toThrow(
      "cbp-guard: block (address_poisoning_lookalike)",
    );
  });
});
