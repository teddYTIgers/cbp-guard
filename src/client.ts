/**
 * Paid calls to the CertBeforePay HTTP API (POST /v1/wallet/check, /v1/gate, /v1/peer/challenge).
 *
 * Each call is paid by x402 from the caller's own wallet (the x402 client the caller passes in).
 * Before signing, the 402 is checked: every offered payTo must be CertBeforePay's payTo and the
 * amount must not exceed the per-route maximum. Nothing here logs keys, signatures or request bodies.
 */
import { decodePaymentRequiredHeader, encodePaymentSignatureHeader } from "@x402/core/http";
import type { PaymentPayload, PaymentRequired } from "@x402/core/types";

export const DEFAULT_CBP_BASE_URL = "https://certbeforepay.com";
/** CertBeforePay's own payTo (Base). Payments to it are never wallet-checked by the guard. */
export const CBP_PAYTO = "0xfcae7e8373264acf7f7d00e9d0171671dcdb095c";
export const KNOWN_RECIPIENTS_MAX = 50;
export const DEFAULT_TIMEOUT_MS = 15_000;

export type CbpPaidPath = "/v1/wallet/check" | "/v1/gate" | "/v1/peer/challenge";

/** Live prices in atomic USDC (6 decimals): wallet/check $0.01, gate $0.02, peer/challenge $0.01. */
export const DEFAULT_MAX_PRICE_ATOMIC: Record<CbpPaidPath, bigint> = {
  "/v1/wallet/check": 10_000n,
  "/v1/gate": 20_000n,
  "/v1/peer/challenge": 10_000n,
};

const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;

export function isAddress(value: unknown): value is string {
  return typeof value === "string" && ADDR_RE.test(value);
}

/** Validates and normalizes known_recipients (max 50 0x+40-hex, lowercased, deduped). */
export function normalizeKnownRecipients(values: unknown): string[] {
  if (values === undefined || values === null) return [];
  if (!Array.isArray(values)) throw new CbpError("invalid_input", "known_recipients must be an array");
  if (values.length > KNOWN_RECIPIENTS_MAX) {
    throw new CbpError("invalid_input", `known_recipients allows at most ${KNOWN_RECIPIENTS_MAX} addresses`);
  }
  const out: string[] = [];
  for (const v of values) {
    if (!isAddress(v)) throw new CbpError("invalid_input", "known_recipients entries must be 0x + 40 hex");
    const low = v.toLowerCase();
    if (!out.includes(low)) out.push(low);
  }
  return out;
}

export type CbpErrorCode =
  | "invalid_input"
  | "network"
  | "timeout"
  | "malformed_body"
  | "bad_402"
  | "payto_mismatch"
  | "price_too_high"
  | "payment_failed";

export class CbpError extends Error {
  readonly code: CbpErrorCode;
  readonly status?: number;
  constructor(code: CbpErrorCode, message: string, status?: number) {
    super(`cbp-guard: ${code}: ${message}`);
    this.name = "CbpError";
    this.code = code;
    this.status = status;
  }
}

/** Anything with the x402 v2 client's createPaymentPayload (e.g. x402Client from @x402/core). */
export interface PaymentClientLike {
  createPaymentPayload(paymentRequired: PaymentRequired): Promise<PaymentPayload>;
}

export interface CbpClientOptions {
  /** The caller's own x402 v2 client; it signs the CertBeforePay payment. Never a CertBeforePay key. */
  paymentClient: PaymentClientLike;
  /** Default https://certbeforepay.com */
  baseUrl?: string;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
  /** Accepted payTo for CertBeforePay's own 402 (default: CBP_PAYTO). */
  cbpPayTo?: string[];
  /** Per-route maximum in atomic USDC; a 402 asking for more is refused, nothing signed. */
  maxPriceAtomic?: Partial<Record<CbpPaidPath, bigint | number | string>>;
}

export interface CbpResponse {
  status: number;
  body: unknown;
  paid: boolean;
  amountAtomic?: string;
}

export class CbpClient {
  readonly baseUrl: string;
  readonly cbpPayTo: string[];
  private readonly paymentClient: PaymentClientLike;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly timeoutMs: number;
  private readonly maxPrice: Record<CbpPaidPath, bigint>;

  constructor(opts: CbpClientOptions) {
    if (!opts?.paymentClient) throw new CbpError("invalid_input", "paymentClient is required");
    this.paymentClient = opts.paymentClient;
    this.baseUrl = (opts.baseUrl ?? DEFAULT_CBP_BASE_URL).replace(/\/+$/, "");
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.cbpPayTo = (opts.cbpPayTo ?? [CBP_PAYTO]).map((a) => a.toLowerCase());
    this.maxPrice = { ...DEFAULT_MAX_PRICE_ATOMIC };
    for (const [k, v] of Object.entries(opts.maxPriceAtomic ?? {})) {
      if (v !== undefined) this.maxPrice[k as CbpPaidPath] = BigInt(v);
    }
  }

  walletCheck(input: {
    address: string;
    chain?: string;
    resource?: string;
    knownRecipients?: string[];
  }): Promise<CbpResponse> {
    if (!isAddress(input?.address)) throw new CbpError("invalid_input", "address must be 0x + 40 hex");
    const body: Record<string, unknown> = { address: input.address };
    if (input.chain) body.chain = input.chain;
    if (input.resource) body.resource = input.resource;
    const known = normalizeKnownRecipients(input.knownRecipients);
    if (known.length > 0) body.known_recipients = known;
    return this.paidPost("/v1/wallet/check", body);
  }

  gate(body: Record<string, unknown>): Promise<CbpResponse> {
    return this.paidPost("/v1/gate", body);
  }

  peerChallenge(body: Record<string, unknown>): Promise<CbpResponse> {
    return this.paidPost("/v1/peer/challenge", body);
  }

  private async post(path: string, body: unknown, headers: Record<string, string> = {}): Promise<Response> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      return await this.fetchImpl(`${this.baseUrl}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", ...headers },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });
    } catch (err) {
      if (ctrl.signal.aborted) throw new CbpError("timeout", `no answer within ${this.timeoutMs} ms`);
      throw new CbpError("network", err instanceof Error ? err.name : "fetch failed");
    } finally {
      clearTimeout(timer);
    }
  }

  private static async readJson(res: Response): Promise<unknown> {
    const text = await res.text();
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch {
      throw new CbpError("malformed_body", "response is not JSON", res.status);
    }
  }

  private paymentRequired(res: Response, body: unknown): PaymentRequired {
    const header = res.headers.get("PAYMENT-REQUIRED");
    let pr: unknown = body;
    if (header) {
      try {
        pr = decodePaymentRequiredHeader(header);
      } catch {
        throw new CbpError("bad_402", "unreadable PAYMENT-REQUIRED header", 402);
      }
    }
    const p = pr as PaymentRequired | null;
    if (!p || typeof p !== "object" || p.x402Version !== 2 || !Array.isArray(p.accepts) || p.accepts.length === 0) {
      throw new CbpError("bad_402", "not an x402 v2 payment requirement", 402);
    }
    return p;
  }

  /** Unpaid POST; on 402 verify payTo + amount, sign with the caller's client, retry once. */
  async paidPost(path: CbpPaidPath, body: Record<string, unknown>): Promise<CbpResponse> {
    const first = await this.post(path, body);
    if (first.status !== 402) {
      return { status: first.status, body: await CbpClient.readJson(first), paid: false };
    }
    const firstBody = await CbpClient.readJson(first).catch(() => null);
    const pr = this.paymentRequired(first, firstBody);
    const max = this.maxPrice[path];
    for (const req of pr.accepts) {
      if (typeof req.payTo !== "string" || !this.cbpPayTo.includes(req.payTo.toLowerCase())) {
        throw new CbpError("payto_mismatch", "402 payTo is not CertBeforePay's payTo; nothing signed", 402);
      }
      let amount: bigint;
      try {
        amount = BigInt(req.amount);
      } catch {
        throw new CbpError("bad_402", "402 amount is not an integer", 402);
      }
      if (amount > max) {
        throw new CbpError("price_too_high", `402 asks ${amount} atomic, max ${max}; nothing signed`, 402);
      }
    }
    const payload = await this.paymentClient.createPaymentPayload(pr);
    const second = await this.post(path, body, { "PAYMENT-SIGNATURE": encodePaymentSignatureHeader(payload) });
    if (second.status === 402) {
      throw new CbpError("payment_failed", "payment was not accepted", 402);
    }
    return {
      status: second.status,
      body: await CbpClient.readJson(second),
      paid: true,
      amountAtomic: payload.accepted?.amount,
    };
  }
}
