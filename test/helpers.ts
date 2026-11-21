import type { PaymentPayload, PaymentRequired, PaymentRequirements } from "@x402/core/types";
import { CBP_PAYTO } from "../src/client.js";

export const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
export const SELLER = `0x${"2".repeat(40)}`;
export const SCAM = `0x${"1".repeat(40)}`;
export const LOOKALIKE = `0x8335${"7".repeat(32)}2913`;
export const KNOWN = `0x1234${"a".repeat(32)}5678`;
/** Fake signature marker used by the fake payment client; must never appear in logs. */
export const FAKE_SIGNATURE = `0x${"ab".repeat(65)}`;

export function requirements(over: Partial<PaymentRequirements> = {}): PaymentRequirements {
  return {
    scheme: "exact",
    network: "eip155:8453",
    asset: USDC_BASE,
    amount: "10000",
    payTo: SELLER,
    maxTimeoutSeconds: 60,
    extra: { name: "USD Coin", version: "2" },
    ...over,
  };
}

export function paymentRequired(
  over: Partial<PaymentRequirements> = {},
  url = "https://seller.example/paid",
): PaymentRequired {
  return {
    x402Version: 2,
    resource: { url, description: "test", mimeType: "application/json" },
    accepts: [requirements(over)],
  };
}

export interface Recorded {
  path: string;
  body: Record<string, unknown>;
  headers: Record<string, string>;
}

export type CbpHandler = (
  path: string,
  body: Record<string, unknown>,
  paid: boolean,
) => {
  status: number;
  body?: unknown;
  raw?: string;
};

/** A mocked CertBeforePay: unpaid POST -> 402 (CBP payTo, price), paid POST -> handler. */
export function fakeCbp(
  handler: CbpHandler,
  opts: { price?: Record<string, string>; payTo?: string; base?: string; fail?: "network" | "hang" } = {},
) {
  const calls: Recorded[] = [];
  const price = { "/v1/wallet/check": "10000", "/v1/gate": "20000", "/v1/peer/challenge": "10000", ...opts.price };
  const base = opts.base ?? "https://certbeforepay.com";
  const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const path = url.pathname;
    const headers = Object.fromEntries(new Headers(init?.headers).entries());
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    calls.push({ path, body, headers });
    if (opts.fail === "network") throw new TypeError("fetch failed");
    if (opts.fail === "hang") {
      await new Promise((_r, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted"))));
    }
    if (`${url.origin}` !== base) return new Response("not found", { status: 404 });
    const paid = "payment-signature" in headers;
    if (!paid && path in price) {
      const pr = paymentRequired(
        { payTo: opts.payTo ?? CBP_PAYTO, amount: price[path as keyof typeof price] },
        `${base}${path}`,
      );
      return new Response(JSON.stringify(pr), { status: 402, headers: { "content-type": "application/json" } });
    }
    const r = handler(path, body, paid);
    return new Response(r.raw ?? JSON.stringify(r.body ?? null), {
      status: r.status,
      headers: { "content-type": "application/json" },
    });
  };
  return { fetch: fetchImpl as typeof globalThis.fetch, calls };
}

export function walletBody(verdict: "clear" | "caution" | "block", extra: Record<string, unknown> = {}) {
  return {
    ok: true,
    verdict,
    reasons: verdict === "clear" ? ["no_adverse_signals"] : [`r_${verdict}`],
    hits: [],
    ...extra,
  };
}

export const LOOKALIKE_BODY = {
  ok: true,
  verdict: "caution",
  reasons: ["address_poisoning_lookalike"],
  sources: ["scam_denylist", "address_poisoning"],
  hits: [
    {
      source: "address_poisoning",
      severity: "caution",
      reason: "address_poisoning_lookalike",
      detail: {
        matched_address: USDC_BASE.toLowerCase(),
        label: "USDC on Base",
        prefix: "8335",
        suffix: "2913",
        origin: "well_known",
        note: "address_poisoning_lookalike: this address starts and ends like 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913 (USDC on Base) but is a different address, a common address-poisoning trick. Check the full address before paying.",
      },
    },
  ],
};

/** Fake x402 payment client: records createPaymentPayload calls, returns a fake signed payload. */
export function fakePaymentClient() {
  const signed: PaymentRequired[] = [];
  const hooks: ((ctx: {
    paymentRequired: PaymentRequired;
    selectedRequirements: PaymentRequirements;
  }) => Promise<unknown>)[] = [];
  const client = {
    signed,
    onBeforePaymentCreation(hook: (typeof hooks)[number]) {
      hooks.push(hook);
      return client;
    },
    async createPaymentPayload(pr: PaymentRequired): Promise<PaymentPayload> {
      const ctx = { paymentRequired: pr, selectedRequirements: pr.accepts[0] };
      for (const h of hooks) await h(ctx);
      signed.push(pr);
      return {
        x402Version: 2,
        resource: pr.resource,
        accepted: pr.accepts[0],
        payload: { signature: FAKE_SIGNATURE, authorization: { to: pr.accepts[0].payTo } },
      };
    },
  };
  return client;
}
