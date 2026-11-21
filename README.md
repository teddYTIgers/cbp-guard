# cbp-guard

cbp-guard checks the wallet your AI agent is about to pay, before it signs, and stops payments to known scam or lookalike wallets. Each wallet check is $0.01 in USDC on Base via x402.

```bash
npm install cbp-guard        # library: the pre-sign hook
npx cbp-guard mcp            # stdio MCP server (needs CBP_GUARD_PRIVATE_KEY)
```

It has two parts:

- **A pre-sign hook** for the official x402 v2 client (`@x402/core`, used by `@x402/fetch` and `@x402/axios`). It runs in `onBeforePaymentCreation`: before your agent signs a 402 payment, it asks [CertBeforePay](https://certbeforepay.com) `POST /v1/wallet/check` about the `payTo`.
- **A stdio MCP server** (`npx cbp-guard mcp`) with the tools `wallet_check`, `gate` and `peer_challenge`.

## What the guard does

| CertBeforePay answer                                                                                                                                   | Default                                                         | Option                                   |
| ------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------- | ---------------------------------------- |
| `block`                                                                                                                                                | refuse; throws `cbp-guard: block (<reason>)`, nothing is signed | none (always refused)                    |
| `caution` (including `address_poisoning_lookalike`)                                                                                                    | refuse                                                          | `onCaution: "block" \| "allow" \| "ask"` |
| `clear`                                                                                                                                                | allow the payment                                               |                                          |
| no usable answer (CertBeforePay down, timeout, `503` stale/misconfigured list, the check's own payment failed, malformed answer, daily budget reached) | refuse                                                          | `failMode: "block" \| "allow"`           |

The defaults are fail-closed. Allowing a caution or a missing answer has to be switched on explicitly.

A **lookalike** is an address that starts and ends like a known address (same first 4 and last 4 hex characters) but is a different address, a common address-poisoning trick. CertBeforePay compares against well-known addresses (such as USDC on Base) and against the addresses you pass as `known_recipients` (your address book or the payTo you used last time, up to 50). When the guard stops a payment, the error carries the verdict, the reasons and, for a lookalike, the matched address, its label and a note.

The wallet check is a risk signal (scam/phishing lists and lookalikes), not an OFAC or sanctions screen, and not a guarantee. CertBeforePay itself never stops a payment; only this guard does, and only if you install it.

## Use the hook

```ts
import { x402Client } from "@x402/core/client";
import { wrapFetchWithPayment } from "@x402/fetch";
import { ExactEvmScheme, toClientEvmSigner } from "@x402/evm";
import { privateKeyToAccount } from "viem/accounts";
import { withCbpGuard } from "cbp-guard";

const account = privateKeyToAccount(process.env.MY_AGENT_KEY as `0x${string}`);
const client = new x402Client().register("eip155:8453", new ExactEvmScheme(toClientEvmSigner(account)));

const guard = withCbpGuard(client, {
  // all optional; these are the defaults unless noted
  onCaution: "block", // "block" | "allow" | "ask" (with ask: async (decision) => boolean)
  failMode: "block", // "block" | "allow"
  knownRecipients: [], // up to 50 0x addresses, or a function returning them
  minAmountUsd: 0, // skip the check for USDC payments below this amount (0 = check all)
  dailyBudgetUsd: 2.5, // USD cap on wallet-check spend per UTC day; Infinity removes the cap
  cacheTtlMs: 5 * 60_000, // cache real verdicts per address; max 15 minutes; 0 disables
  baseUrl: "https://certbeforepay.com",
  onDecision: (d) => console.log(d.action, d.verdict, d.reasons),
});

const fetchWithPay = wrapFetchWithPayment(fetch, client);
await fetchWithPay("https://seller.example/paid"); // throws "... cbp-guard: block (...)" when stopped
```

- Each wallet check is paid by x402 from **your own wallet** (the client you pass in), at $0.01. The guard checks CertBeforePay's 402 before signing: the payTo must be CertBeforePay's, the payment must be USDC on Base (`eip155:8453`), and the amount must not exceed $0.01 (gate $0.02, peer challenge $0.01; override with `maxPriceAtomic`).
- Payments to CertBeforePay's own payTo (`0xfcae7e8373264acf7f7d00e9d0171671dcdb095c`) are never checked, so you do not pay us to check us (and the check's own payment does not loop).
- Only real verdicts are cached, for minutes. Failures such as a `503` are never cached.
- Every request to CertBeforePay carries `User-Agent: cbp-guard/<version>`.
- The guard sends CertBeforePay the payTo, the chain, your `known_recipients` (if any) and the seller's resource URL without its query string or fragment (origin and path only).
- `baseUrl` must use https. Plain http is accepted only for `localhost`, `127.0.0.1` and `[::1]`, or for any host if you set `allowInsecureHttp: true` (for local testing only).
- Each request to CertBeforePay has one deadline (15 seconds by default) that covers reading the whole answer, and answers over 64 KB are rejected. Either way there is no usable answer, so `failMode` applies.
- Legacy x402 v1 packages and wrapping a viem account (transfers, approvals) are not supported in this release.

### Daily budget

By default the guard spends at most $2.50 in USDC per UTC day on wallet checks. The amount is reserved before each check's payment is signed, so checks running in parallel cannot go over the cap, and a signed payment counts even if the answer that comes back is unusable. When the budget is used up, the guard treats the check as having no usable answer, so with the default `failMode: "block"` payments are refused until the next UTC day. Cached verdicts and skipped payments do not count against the budget. Set `dailyBudgetUsd` to raise or lower the cap, or to `Infinity` to remove it. The budget is kept in memory per guard, so it starts again when your process restarts.

## Examples

### @x402/fetch

```ts
import { x402Client } from "@x402/core/client";
import { ExactEvmScheme, toClientEvmSigner } from "@x402/evm";
import { wrapFetchWithPayment } from "@x402/fetch";
import { withCbpGuard } from "cbp-guard";
import { privateKeyToAccount } from "viem/accounts";

const account = privateKeyToAccount(process.env.MY_AGENT_KEY as `0x${string}`);
const client = new x402Client().register("eip155:8453", new ExactEvmScheme(toClientEvmSigner(account)));
withCbpGuard(client, { knownRecipients: ["0x1111111111111111111111111111111111111111"] });

const fetchWithPay = wrapFetchWithPayment(fetch, client);
try {
  const res = await fetchWithPay("https://seller.example/paid");
  console.log(res.status, await res.text());
} catch (err) {
  console.error((err as Error).message); // "... cbp-guard: block (...)" when the guard stopped it
}
```

### Coinbase AgentKit

AgentKit's built-in `x402ActionProvider` builds its own x402 client inside each action and has no hook option, so cbp-guard cannot attach to it. Instead, add a custom action that builds a guarded client from the AgentKit wallet, and use it in place of the built-in x402 actions.

```ts
import { AgentKit, CdpEvmWalletProvider, customActionProvider, type EvmWalletProvider } from "@coinbase/agentkit";
import { x402Client } from "@x402/core/client";
import { ExactEvmScheme, toClientEvmSigner } from "@x402/evm";
import { wrapFetchWithPayment } from "@x402/fetch";
import { withCbpGuard } from "cbp-guard";
import { z } from "zod";

// Reads CDP_API_KEY_ID, CDP_API_KEY_SECRET and CDP_WALLET_SECRET from the environment.
const walletProvider = await CdpEvmWalletProvider.configureWithWallet({ networkId: "base-mainnet" });

const guardedPaidFetch = customActionProvider<EvmWalletProvider>({
  name: "guarded_paid_fetch",
  description: "Fetch a URL and pay its x402 402 only after cbp-guard checks the payTo.",
  schema: z.object({ url: z.string().url() }),
  invoke: async (wallet, args: { url: string }) => {
    const client = new x402Client().register("eip155:8453", new ExactEvmScheme(toClientEvmSigner(wallet.toSigner())));
    withCbpGuard(client);
    try {
      const res = await wrapFetchWithPayment(fetch, client)(args.url);
      return `${res.status} ${await res.text()}`;
    } catch (err) {
      return `Payment refused: ${(err as Error).message}`;
    }
  },
});

const agentkit = await AgentKit.from({ walletProvider, actionProviders: [guardedPaidFetch] });
```

This example was type-checked against `@coinbase/agentkit` 0.10.4 and `@x402/*` 2.32.0 (zod 3, as AgentKit uses). It has not been run against a live CDP wallet.

## Use the MCP server

```bash
CBP_GUARD_PRIVATE_KEY=0x... npx cbp-guard mcp
```

Example client config:

```json
{
  "mcpServers": {
    "cbp-guard": {
      "command": "npx",
      "args": ["-y", "cbp-guard", "mcp"],
      "env": { "CBP_GUARD_PRIVATE_KEY": "<your low-balance wallet key>" }
    }
  }
}
```

| Tool                                                                         | Endpoint                  | Price |
| ---------------------------------------------------------------------------- | ------------------------- | ----- |
| `wallet_check` (`address`, optional `chain`, `resource`, `known_recipients`) | `POST /v1/wallet/check`   | $0.01 |
| `gate` (`skill`, `skills`, `mcp` or `content`)                               | `POST /v1/gate`           | $0.02 |
| `peer_challenge` (`certificate`, optional `min_score`, `require_tier`)       | `POST /v1/peer/challenge` | $0.01 |

- `CBP_GUARD_PRIVATE_KEY` (required): the private key of **your** wallet that pays for each call via x402 (USDC on Base). The server refuses to start without it. Use a dedicated low-balance wallet. The key is read from the environment only; it is never logged, returned or written to disk, and neither is any payment signature. If the key is invalid, the error says so without repeating it.
- `CBP_GUARD_BASE_URL` (optional): default `https://certbeforepay.com`. It must use https; plain http is accepted only for `localhost`, `127.0.0.1` and `[::1]` (the MCP server has no `allowInsecureHttp` setting).
- `CBP_GUARD_DAILY_BUDGET_USD` (optional): the most this server process spends per UTC day, default `2.50`. The price of each paid call is reserved against it before signing; when it is used up, tools return a `budget_exhausted` error and nothing is signed until the next UTC day. Set it to `Infinity` to remove the cap. It is kept in memory, so it starts again when the server restarts.
- CertBeforePay's own `POST /mcp` is discovery-only; this stdio server is the one that performs paid calls.

### Use a dedicated low-balance wallet

Use a dedicated wallet that holds only a small USDC balance for `CBP_GUARD_PRIVATE_KEY`, not your main wallet. Top it up as needed. If the key ever leaks, only that small balance is at risk.

## Development

```bash
npm ci
npm run typecheck && npm run lint && npm test && npm run build
```

All CertBeforePay HTTP calls in the tests are mocked; the tests never reach production or spend USDC. Test keys are generated at run time and never funded.

## Releases

Releases are published to npm with provenance from GitHub Actions.

## License

MIT. This package contains no scam-list data; lists stay on the CertBeforePay server.
