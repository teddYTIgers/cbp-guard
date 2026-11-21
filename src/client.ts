/**
 * Paid calls to the CertBeforePay HTTP API (POST /v1/wallet/check, /v1/gate, /v1/peer/challenge).
 *
 * Each call is paid by x402 from the caller's own wallet (the x402 client the caller passes in).
 * Before signing, the 402 is checked: every offered payTo must be CertBeforePay's payTo and the
 * amount must not exceed the per-route maximum. Nothing here logs keys, signatures or request bodies.
 */
import { decodePaymentRequiredHeader, encodePaymentSignatureHeader } from "@x402/core/http";
import type { PaymentPayload, PaymentRequired } from "@x402/core/types";
import type { SpendBudget } from "./budget.js";
import { CbpError } from "./errors.js";
import { USER_AGENT } from "./version.js";

export { CbpError, type CbpErrorCode } from "./errors.js";

export const DEFAULT_CBP_BASE_URL = "https://certbeforepay.com";
/** CertBeforePay's own payTo (Base). Payments to it are never wallet-checked by the guard. */
export const CBP_PAYTO = "0xfcae7e8373264acf7f7d00e9d0171671dcdb095c";
export const KNOWN_RECIPIENTS_MAX = 50;
export const DEFAULT_TIMEOUT_MS = 15_000;
/** Largest CertBeforePay response body read (bytes); bigger -> malformed_body. */
export const MAX_RESPONSE_BYTES = 64 * 1024;
/** CertBeforePay's own 402 must be for USDC on Base; anything else is refused before signing. */
export const CBP_NETWORK = "eip155:8453";
export const CBP_ASSET = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
/** Longest resource URL forwarded to CertBeforePay (longer -> origin only). */
export const MAX_RESOURCE_LENGTH = 2048;

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

/** Anything with the x402 v2 client's createPaymentPayload (e.g. x402Client from @x402/core). */
export interface PaymentClientLike {
  createPaymentPayload(paymentRequired: PaymentRequired): Promise<PaymentPayload>;
}

/**
 * The resource URL sent to CertBeforePay: for http(s) URLs, the query string, fragment and any
 * user:password are removed (origin + path only; origin alone if still over 2048 characters).
 * Other strings (e.g. a bare domain) pass through if at most 2048 characters, else are dropped.
 */
export function sanitizeResource(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length === 0) return undefined;
  let url: URL | undefined;
  try {
    url = new URL(value);
  } catch {
    url = undefined;
  }
  if (url && (url.protocol === "https:" || url.protocol === "http:")) {
    const stripped = `${url.origin}${url.pathname}`;
    return stripped.length <= MAX_RESOURCE_LENGTH ? stripped : url.origin;
  }
  if (url) return undefined;
  return value.length <= MAX_RESOURCE_LENGTH ? value : undefined;
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** https only; plain http only for localhost or with allowInsecureHttp (tests). */
export function checkBaseUrl(raw: string, allowInsecureHttp = false): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new CbpError("invalid_input", "baseUrl is not a valid URL");
  }
  if (url.protocol === "https:") return raw.replace(/\/+$/, "");
  if (url.protocol === "http:" && (LOCAL_HOSTS.has(url.hostname) || allowInsecureHttp)) return raw.replace(/\/+$/, "");
  throw new CbpError("invalid_input", "baseUrl must use https (plain http only for localhost)");
}

export interface CbpClientOptions {
  /** The caller's own x402 v2 client; it signs the CertBeforePay payment. Never a CertBeforePay key. */
  paymentClient: PaymentClientLike;
  /** Default https://certbeforepay.com. Must be https (plain http only for localhost). */
  baseUrl?: string;
  /** Tests only: allow plain http for a non-localhost baseUrl. */
  allowInsecureHttp?: boolean;
  /** Daily spend cap shared by every paid call of this client (default: none at this level). */
  budget?: SpendBudget;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
  /** Accepted payTo for CertBeforePay's own 402 (default: CBP_PAYTO). */
  cbpPayTo?: string[];
  /** Per-route maximum in atomic USDC; a 402 asking for more is refused, nothing signed. */
  maxPriceAtomic?: Partial<Record<CbpPaidPath, bigint | number | string>>;
}

interface RawResponse {
  status: number;
  headers: Headers;
  text: string;
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
  readonly budget?: SpendBudget;

  constructor(opts: CbpClientOptions) {
    if (!opts?.paymentClient) throw new CbpError("invalid_input", "paymentClient is required");
    this.paymentClient = opts.paymentClient;
    this.baseUrl = checkBaseUrl(opts.baseUrl ?? DEFAULT_CBP_BASE_URL, opts.allowInsecureHttp === true);
    this.budget = opts.budget;
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
    const resource = sanitizeResource(input.resource);
    if (resource) body.resource = resource;
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

  /** Max price (atomic USDC) this client will sign for a route. */
  maxPriceFor(path: CbpPaidPath): bigint {
    return this.maxPrice[path];
  }

  /**
   * One POST with a single deadline (timeoutMs) covering connect, headers and the whole body,
   * and a body size cap (MAX_RESPONSE_BYTES).
   */
  private async request(path: string, body: unknown, headers: Record<string, string> = {}): Promise<RawResponse> {
    const ctrl = new AbortController();
    let timedOut = false;
    let onAbort: (() => void) | undefined;
    const deadline = new Promise<never>((_resolve, reject) => {
      onAbort = () => reject(new CbpError("timeout", `no complete answer within ${this.timeoutMs} ms`));
      ctrl.signal.addEventListener("abort", onAbort);
    });
    deadline.catch(() => {});
    const timer = setTimeout(() => {
      timedOut = true;
      ctrl.abort();
    }, this.timeoutMs);
    try {
      let res: Response;
      try {
        res = await Promise.race([
          this.fetchImpl(`${this.baseUrl}${path}`, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              accept: "application/json",
              ...headers,
              "user-agent": USER_AGENT,
            },
            body: JSON.stringify(body),
            signal: ctrl.signal,
          }),
          deadline,
        ]);
      } catch (err) {
        if (err instanceof CbpError) throw err;
        if (timedOut) throw new CbpError("timeout", `no complete answer within ${this.timeoutMs} ms`);
        throw new CbpError("network", err instanceof Error ? err.name : "fetch failed");
      }
      const text = await Promise.race([CbpClient.readCapped(res), deadline]);
      return { status: res.status, headers: res.headers, text };
    } catch (err) {
      if (err instanceof CbpError) throw err;
      if (timedOut) throw new CbpError("timeout", `no complete answer within ${this.timeoutMs} ms`);
      throw new CbpError("network", err instanceof Error ? err.name : "read failed");
    } finally {
      clearTimeout(timer);
      if (onAbort) ctrl.signal.removeEventListener("abort", onAbort);
      if (!ctrl.signal.aborted) ctrl.abort();
    }
  }

  private static async readCapped(res: Response): Promise<string> {
    const declared = Number(res.headers.get("content-length") ?? "");
    if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
      await res.body?.cancel().catch(() => {});
      throw new CbpError("malformed_body", `response body over ${MAX_RESPONSE_BYTES} bytes`, res.status);
    }
    if (!res.body) return "";
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => {});
        throw new CbpError("malformed_body", `response body over ${MAX_RESPONSE_BYTES} bytes`, res.status);
      }
      chunks.push(value);
    }
    const all = new Uint8Array(total);
    let off = 0;
    for (const ch of chunks) {
      all.set(ch, off);
      off += ch.byteLength;
    }
    return new TextDecoder().decode(all);
  }

  private static parseJson(res: RawResponse): unknown {
    if (!res.text) return null;
    try {
      return JSON.parse(res.text);
    } catch {
      throw new CbpError("malformed_body", "response is not JSON", res.status);
    }
  }

  private paymentRequired(res: RawResponse, body: unknown): PaymentRequired {
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

  /**
   * Unpaid POST; on 402 verify payTo, network, asset and amount, reserve the amount in the daily
   * budget (synchronously), sign with the caller's client, retry once. A signed payment stays
   * counted at its signed amount whatever happens next.
   */
  async paidPost(path: CbpPaidPath, body: Record<string, unknown>): Promise<CbpResponse> {
    const first = await this.request(path, body);
    if (first.status !== 402) {
      return { status: first.status, body: CbpClient.parseJson(first), paid: false };
    }
    let firstBody: unknown = null;
    try {
      firstBody = CbpClient.parseJson(first);
    } catch {
      firstBody = null;
    }
    const pr = this.paymentRequired(first, firstBody);
    const max = this.maxPrice[path];
    let highest = 0n;
    for (const req of pr.accepts) {
      if (typeof req.payTo !== "string" || !this.cbpPayTo.includes(req.payTo.toLowerCase())) {
        throw new CbpError("payto_mismatch", "402 payTo is not CertBeforePay's payTo; nothing signed", 402);
      }
      if (req.network !== CBP_NETWORK) {
        throw new CbpError("network_mismatch", `402 network is not ${CBP_NETWORK}; nothing signed`, 402);
      }
      if (typeof req.asset !== "string" || req.asset.toLowerCase() !== CBP_ASSET) {
        throw new CbpError("asset_mismatch", "402 asset is not USDC on Base; nothing signed", 402);
      }
      let amount: bigint;
      try {
        amount = BigInt(req.amount);
      } catch {
        throw new CbpError("bad_402", "402 amount is not an integer", 402);
      }
      if (amount < 0n) throw new CbpError("bad_402", "402 amount is negative", 402);
      if (amount > max) {
        throw new CbpError("price_too_high", `402 asks ${amount} atomic, max ${max}; nothing signed`, 402);
      }
      if (amount > highest) highest = amount;
    }
    // Synchronous reservation between the 402 check and signing: concurrent calls cannot overshoot.
    const reservation = this.budget ? this.budget.reserve(highest) : null;
    if (this.budget && !reservation) {
      throw new CbpError("budget_exhausted", "daily budget reached; nothing signed", 402);
    }
    let payload: PaymentPayload;
    try {
      payload = await this.paymentClient.createPaymentPayload(pr);
    } catch (err) {
      if (reservation) this.budget?.release(reservation);
      throw err;
    }
    let signed = highest;
    try {
      signed = BigInt(payload.accepted?.amount ?? highest);
    } catch {
      signed = highest;
    }
    if (reservation && signed < highest) this.budget?.release(reservation, highest - signed);
    const second = await this.request(path, body, { "PAYMENT-SIGNATURE": encodePaymentSignatureHeader(payload) });
    if (second.status === 402) {
      throw new CbpError("payment_failed", "payment was not accepted", 402);
    }
    return {
      status: second.status,
      body: CbpClient.parseJson(second),
      paid: true,
      amountAtomic: payload.accepted?.amount,
    };
  }
}
