/**
 * Pre-sign hook for the official x402 v2 client (`onBeforePaymentCreation`).
 *
 * Before the agent signs a 402 payment, the payTo is checked with CertBeforePay
 * (POST /v1/wallet/check, $0.01, paid from the caller's own wallet).
 * Defaults are fail-closed: block -> refuse, caution -> refuse (onCaution "block"),
 * no usable answer -> refuse (failMode "block").
 */
import type { BeforePaymentCreationHook, PaymentCreationContext } from "@x402/core/client";
import { DEFAULT_DAILY_BUDGET_USD, SpendBudget } from "./budget.js";
import {
  CBP_PAYTO,
  CbpClient,
  type CbpClientOptions,
  CbpError,
  isAddress,
  normalizeKnownRecipients,
  type PaymentClientLike,
} from "./client.js";

export type Verdict = "clear" | "caution" | "block";

export interface LookalikeDetail {
  matched_address?: string;
  label?: string;
  note?: string;
}

export interface GuardDecision {
  action: "allow" | "block" | "skip";
  /** clear | caution | block from CertBeforePay, or "unavailable" when no usable answer. */
  verdict: Verdict | "unavailable" | "skipped";
  payTo: string;
  chain?: string;
  reasons: string[];
  lookalike?: LookalikeDetail;
  /** Why the check was skipped or failed (e.g. cbp_payto, below_min_amount, timeout, http_503). */
  detail?: string;
  cached?: boolean;
}

export class CbpGuardError extends Error {
  readonly decision: GuardDecision;
  constructor(decision: GuardDecision) {
    const reason = decision.reasons[0] ?? decision.detail ?? decision.verdict;
    super(`cbp-guard: block (${reason})`);
    this.name = "CbpGuardError";
    this.decision = decision;
  }
}

export interface GuardOptions extends Omit<CbpClientOptions, "paymentClient"> {
  /** "block" (default) | "allow" | "ask" for a caution verdict (incl. address_poisoning_lookalike). */
  onCaution?: "block" | "allow" | "ask";
  /** Called when onCaution is "ask"; return true to pay. Missing or throwing -> block. */
  ask?: (decision: GuardDecision) => boolean | Promise<boolean>;
  /** "block" (default) | "allow" when CertBeforePay gives no usable answer. */
  failMode?: "block" | "allow";
  /** Address book / last payTo, forwarded as known_recipients (max 50). */
  knownRecipients?: string[] | (() => string[] | Promise<string[]>);
  /** Skip the check for payments below this many USD (USDC only). Default 0: check every payment. */
  minAmountUsd?: number;
  /**
   * Cap on wallet-check spend per UTC day in USD (per guard instance, in memory). Default $2.50.
   * The amount is reserved before each check's payment is signed (safe under concurrency) and a
   * signed payment counts at its signed amount even if the answer is unusable. Cache hits and
   * skips cost nothing. When reached -> failMode. Infinity removes the cap.
   */
  dailyBudgetUsd?: number;
  /** Cache real verdicts per address for this long. Default 5 minutes, max 15 minutes, 0 disables. */
  cacheTtlMs?: number;
  /** Extra payTo addresses never checked (CertBeforePay's own payTo is always skipped). */
  skipPayTo?: string[];
  /** Observe every decision (no keys or signatures are ever passed). */
  onDecision?: (decision: GuardDecision) => void;
  /** Clock for tests. */
  now?: () => number;
}

export { DEFAULT_DAILY_BUDGET_USD };
export const DEFAULT_CACHE_TTL_MS = 5 * 60_000;
export const MAX_CACHE_TTL_MS = 15 * 60_000;
/** USDC contracts whose 6-decimal amounts minAmountUsd understands (Base, Base Sepolia). */
const USDC_ASSETS: Record<string, string> = {
  "eip155:8453": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
  "eip155:84532": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
};

interface CacheEntry {
  at: number;
  verdict: Verdict;
  reasons: string[];
  lookalike?: LookalikeDetail;
}

function extractLookalike(body: Record<string, unknown>): LookalikeDetail | undefined {
  const hits = Array.isArray(body.hits) ? body.hits : [];
  for (const h of hits) {
    if (h && typeof h === "object" && (h as Record<string, unknown>).reason === "address_poisoning_lookalike") {
      const d = ((h as Record<string, unknown>).detail ?? {}) as Record<string, unknown>;
      return {
        matched_address: typeof d.matched_address === "string" ? d.matched_address : undefined,
        label: typeof d.label === "string" ? d.label : undefined,
        note: typeof d.note === "string" ? d.note : undefined,
      };
    }
  }
  return undefined;
}

export class CbpGuard {
  readonly client: CbpClient;
  private readonly opts: GuardOptions;
  private readonly cache = new Map<string, CacheEntry>();
  private readonly skip: Set<string>;
  private readonly ttl: number;
  readonly budget: SpendBudget;

  constructor(paymentClient: PaymentClientLike, opts: GuardOptions = {}) {
    let budget: SpendBudget;
    try {
      budget = new SpendBudget(opts.dailyBudgetUsd ?? DEFAULT_DAILY_BUDGET_USD, () => (opts.now ?? Date.now)());
    } catch {
      throw new CbpError("invalid_input", "dailyBudgetUsd must be a number >= 0 (Infinity for no cap)");
    }
    this.budget = budget;
    this.client = new CbpClient({ ...opts, paymentClient, budget });
    this.opts = opts;
    this.skip = new Set([CBP_PAYTO, ...this.client.cbpPayTo, ...(opts.skipPayTo ?? [])].map((a) => a.toLowerCase()));
    const ttl = opts.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.ttl = Math.max(0, Math.min(ttl, MAX_CACHE_TTL_MS));
  }

  private now(): number {
    return (this.opts.now ?? Date.now)();
  }

  private async knownRecipients(): Promise<string[]> {
    const k = this.opts.knownRecipients;
    const list = typeof k === "function" ? await k() : k;
    return normalizeKnownRecipients(list);
  }

  private budgetAllows(): boolean {
    // Cheap early check (no CertBeforePay call when today's cap is already used up); the
    // authoritative reservation happens in CbpClient right before signing.
    return this.budget.fits(this.client.maxPriceFor("/v1/wallet/check"));
  }

  private belowMin(chain: string, asset: string, amount: string): boolean {
    const min = this.opts.minAmountUsd ?? 0;
    if (!(min > 0)) return false;
    if (USDC_ASSETS[chain] !== asset.toLowerCase()) return false;
    try {
      return Number(BigInt(amount)) / 1_000_000 < min;
    } catch {
      return false;
    }
  }

  private emit(d: GuardDecision): GuardDecision {
    try {
      this.opts.onDecision?.(d);
    } catch {
      // observer errors never change the decision
    }
    return d;
  }

  private unavailable(payTo: string, chain: string, detail: string): GuardDecision {
    const allow = this.opts.failMode === "allow";
    return { action: allow ? "allow" : "block", verdict: "unavailable", payTo, chain, reasons: [], detail };
  }

  private async onVerdict(base: GuardDecision): Promise<GuardDecision> {
    if (base.verdict === "clear") return { ...base, action: "allow" };
    if (base.verdict === "caution") {
      const mode = this.opts.onCaution ?? "block";
      if (mode === "allow") return { ...base, action: "allow" };
      if (mode === "ask" && this.opts.ask) {
        try {
          return { ...base, action: (await this.opts.ask(base)) === true ? "allow" : "block" };
        } catch {
          return { ...base, action: "block" };
        }
      }
      return { ...base, action: "block" };
    }
    return { ...base, action: "block" };
  }

  /** Decide for one payTo. Never throws; failures become failMode decisions. */
  async decide(input: {
    payTo: string;
    chain?: string;
    asset?: string;
    amount?: string;
    resource?: string;
  }): Promise<GuardDecision> {
    const chain = input.chain ?? "eip155:8453";
    const payTo = typeof input.payTo === "string" ? input.payTo : "";
    if (!isAddress(payTo)) {
      return this.emit({ action: "block", verdict: "block", payTo, chain, reasons: ["invalid_payto"] });
    }
    const low = payTo.toLowerCase();
    if (this.skip.has(low)) {
      return this.emit({ action: "skip", verdict: "skipped", payTo, chain, reasons: [], detail: "cbp_payto" });
    }
    if (input.asset && input.amount && this.belowMin(chain, input.asset, input.amount)) {
      return this.emit({ action: "skip", verdict: "skipped", payTo, chain, reasons: [], detail: "below_min_amount" });
    }
    let known: string[];
    try {
      known = await this.knownRecipients();
    } catch {
      return this.emit(this.unavailable(payTo, chain, "invalid_known_recipients"));
    }
    const key = `${chain}|${low}|${known.join(",")}`;
    const hit = this.cache.get(key);
    if (hit && this.ttl > 0 && this.now() - hit.at < this.ttl) {
      return this.emit(
        await this.onVerdict({
          action: "block",
          verdict: hit.verdict,
          payTo,
          chain,
          reasons: hit.reasons,
          lookalike: hit.lookalike,
          cached: true,
        }),
      );
    }
    if (!this.budgetAllows()) return this.emit(this.unavailable(payTo, chain, "daily_budget_reached"));

    let res: Awaited<ReturnType<CbpClient["walletCheck"]>>;
    try {
      res = await this.client.walletCheck({ address: payTo, chain, resource: input.resource, knownRecipients: known });
    } catch (err) {
      if (err instanceof CbpError && err.code === "budget_exhausted") {
        return this.emit(this.unavailable(payTo, chain, "daily_budget_reached"));
      }
      return this.emit(this.unavailable(payTo, chain, err instanceof CbpError ? err.code : "check_failed"));
    }
    if (res.status !== 200) return this.emit(this.unavailable(payTo, chain, `http_${res.status}`));
    const body = res.body as Record<string, unknown> | null;
    const verdict = body?.verdict;
    if (body?.ok !== true || (verdict !== "clear" && verdict !== "caution" && verdict !== "block")) {
      return this.emit(this.unavailable(payTo, chain, "malformed_body"));
    }
    const reasons = Array.isArray(body.reasons) ? body.reasons.filter((r): r is string => typeof r === "string") : [];
    const lookalike = extractLookalike(body);
    if (this.ttl > 0) this.cache.set(key, { at: this.now(), verdict, reasons, lookalike });
    return this.emit(await this.onVerdict({ action: "block", verdict, payTo, chain, reasons, lookalike }));
  }

  /** The x402 v2 onBeforePaymentCreation hook. Throws CbpGuardError to stop signing. */
  readonly hook = async (ctx: PaymentCreationContext): Promise<void> => {
    const req = ctx.selectedRequirements;
    const d = await this.decide({
      payTo: req?.payTo,
      chain: req?.network,
      asset: req?.asset,
      amount: req?.amount,
      resource: ctx.paymentRequired?.resource?.url,
    });
    if (d.action === "block") throw new CbpGuardError(d);
  };

  clearCache(): void {
    this.cache.clear();
  }
}

/** Anything with x402Client's onBeforePaymentCreation + createPaymentPayload. */
export interface HookableClient extends PaymentClientLike {
  onBeforePaymentCreation(hook: BeforePaymentCreationHook): unknown;
}

/**
 * Register the guard on the caller's x402 v2 client and return the guard.
 * The same client pays CertBeforePay for each check; that payment goes to CertBeforePay's own
 * payTo, which the guard skips, so there is no recursion.
 */
export function withCbpGuard<C extends HookableClient>(client: C, opts: GuardOptions = {}): CbpGuard {
  const guard = new CbpGuard(client, opts);
  client.onBeforePaymentCreation(guard.hook);
  return guard;
}
