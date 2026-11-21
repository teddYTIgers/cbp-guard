/** Errors from cbp-guard. Messages are ours and never contain keys, signatures or request bodies. */
export type CbpErrorCode =
  | "invalid_input"
  | "network"
  | "timeout"
  | "malformed_body"
  | "bad_402"
  | "payto_mismatch"
  | "price_too_high"
  | "network_mismatch"
  | "asset_mismatch"
  | "budget_exhausted"
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
