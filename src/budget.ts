/**
 * Daily spend cap for CertBeforePay calls, in atomic USDC, per UTC day, in memory.
 *
 * reserve() is synchronous, so concurrent calls can never reserve more than the cap: it runs
 * after CertBeforePay's 402 is verified and before the payment is signed. A reservation is
 * released only when nothing was signed; once a payment is signed it counts at the signed
 * amount, even if the answer that follows is unusable.
 */
import { CbpError } from "./errors.js";

export const DEFAULT_DAILY_BUDGET_USD = 1;

export interface Reservation {
  day: string;
  amount: bigint;
}

export class SpendBudget {
  /** Cap in atomic USDC (6 decimals); null = no cap. */
  readonly capAtomic: bigint | null;
  private readonly now: () => number;
  private day = "";
  private spent = 0n;

  constructor(dailyBudgetUsd: number = DEFAULT_DAILY_BUDGET_USD, now: () => number = Date.now) {
    if (typeof dailyBudgetUsd !== "number" || Number.isNaN(dailyBudgetUsd) || dailyBudgetUsd < 0) {
      throw new CbpError("invalid_input", "daily budget must be a number >= 0 (Infinity for no cap)");
    }
    this.capAtomic =
      dailyBudgetUsd === Number.POSITIVE_INFINITY ? null : BigInt(Math.floor(dailyBudgetUsd * 1e6 + 1e-6));
    this.now = now;
  }

  private roll(): void {
    const day = new Date(this.now()).toISOString().slice(0, 10);
    if (day !== this.day) {
      this.day = day;
      this.spent = 0n;
    }
  }

  /** Spent (signed or reserved) today, in atomic USDC. */
  spentAtomic(): bigint {
    this.roll();
    return this.spent;
  }

  /** True when `amount` more would still fit under the cap today. */
  fits(amount: bigint): boolean {
    this.roll();
    return this.capAtomic === null || this.spent + amount <= this.capAtomic;
  }

  /** Reserve `amount` synchronously; null (nothing reserved) when it would exceed the cap. */
  reserve(amount: bigint): Reservation | null {
    if (amount < 0n || !this.fits(amount)) return null;
    this.spent += amount;
    return { day: this.day, amount };
  }

  /** Give back part or all of a reservation (nothing signed, or signed for less). Same UTC day only. */
  release(r: Reservation, amount: bigint = r.amount): void {
    this.roll();
    if (r.day !== this.day) return;
    const back = amount > r.amount ? r.amount : amount;
    this.spent = this.spent > back ? this.spent - back : 0n;
  }
}
