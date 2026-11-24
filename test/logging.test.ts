import { readFileSync } from "node:fs";
import { generatePrivateKey } from "viem/accounts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main } from "../src/cli.js";
import { withCbpGuard } from "../src/guard.js";
import { KEY_ENV, paymentClientFromEnv } from "../src/mcp.js";
import { FAKE_SIGNATURE, fakeCbp, fakePaymentClient, LOOKALIKE_BODY, paymentRequired, walletBody } from "./helpers.js";

let out = "";
beforeEach(() => {
  out = "";
  const capture = (chunk: unknown) => {
    out += String(chunk);
    return true;
  };
  vi.spyOn(process.stdout, "write").mockImplementation(capture as never);
  vi.spyOn(process.stderr, "write").mockImplementation(capture as never);
  for (const m of ["log", "info", "warn", "error", "debug"] as const) {
    vi.spyOn(console, m).mockImplementation((...a: unknown[]) => {
      out += `${a.map(String).join(" ")}\n`;
    });
  }
});
afterEach(() => {
  vi.restoreAllMocks();
  delete process.env[KEY_ENV];
});

describe("no key, signature or env value in output", () => {
  it("guard decisions and errors never contain the payment signature", async () => {
    for (const body of [walletBody("clear"), walletBody("block"), LOOKALIKE_BODY]) {
      const cbp = fakeCbp(() => ({ status: 200, body }));
      const pay = fakePaymentClient();
      const seen: unknown[] = [];
      withCbpGuard(pay, { fetch: cbp.fetch, onDecision: (d) => seen.push(d) });
      const err = await pay.createPaymentPayload(paymentRequired()).catch((e) => e);
      const blob = `${out}${JSON.stringify(seen)}${err ? `${err.message}${JSON.stringify(err.decision)}` : ""}`;
      expect(blob).not.toContain(FAKE_SIGNATURE.slice(2, 40));
    }
    expect(out).toBe("");
  });

  it("the key loader hints without a key; a malformed key is never echoed (0.1.2: mcp starts keyless)", async () => {
    const noKey = await paymentClientFromEnv({}).catch((e) => e);
    expect(noKey.message).toContain(KEY_ENV);
    const secretish = `0x${"c".repeat(63)}z`;
    const bad = await paymentClientFromEnv({ [KEY_ENV]: secretish }).catch((e) => e);
    expect(bad.message).not.toContain(secretish);
    expect(bad.message).not.toContain("c".repeat(20));
    expect(out).not.toContain("c".repeat(20));
  });

  it("cli --version and usage", async () => {
    expect(await main(["--version"])).toBe(0);
    expect(out.trim()).toBe(JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version);
    out = "";
    expect(await main(["nope"])).toBe(2);
    expect(out).toContain("cbp-guard mcp");
  });

  it("a valid key is never printed by the library", async () => {
    const key = generatePrivateKey();
    const { paymentClientFromEnv } = await import("../src/mcp.js");
    await paymentClientFromEnv({ [KEY_ENV]: key });
    expect(out).not.toContain(key.slice(2));
  });
});
