import { encodePaymentRequiredHeader } from "@x402/core/http";
import { describe, expect, it } from "vitest";
import { CBP_PAYTO, CbpClient, CbpError, normalizeKnownRecipients } from "../src/client.js";
import { FAKE_SIGNATURE, fakeCbp, fakePaymentClient, KNOWN, paymentRequired, SELLER, walletBody } from "./helpers.js";

describe("CbpClient", () => {
  it("wallet check: unpaid 402 -> pays $0.01 to CertBeforePay -> returns body; known_recipients forwarded", async () => {
    const cbp = fakeCbp(() => ({ status: 200, body: walletBody("clear") }));
    const pay = fakePaymentClient();
    const c = new CbpClient({ paymentClient: pay, fetch: cbp.fetch });
    const r = await c.walletCheck({ address: SELLER, chain: "eip155:8453", knownRecipients: [KNOWN] });
    expect(r).toMatchObject({ status: 200, paid: true, amountAtomic: "10000" });
    expect(cbp.calls).toHaveLength(2);
    expect(cbp.calls[0].headers).not.toHaveProperty("payment-signature");
    expect(cbp.calls[1].headers["payment-signature"]).toBeTruthy();
    expect(cbp.calls[1].body).toEqual({
      address: SELLER,
      chain: "eip155:8453",
      known_recipients: [KNOWN.toLowerCase()],
    });
    expect(pay.signed[0].accepts[0].payTo).toBe(CBP_PAYTO);
  });

  it("reads the 402 from the PAYMENT-REQUIRED header too", async () => {
    let n = 0;
    const fetchImpl = (async (_u: RequestInfo | URL, init?: RequestInit) => {
      n++;
      if (n === 1) {
        const pr = paymentRequired({ payTo: CBP_PAYTO, amount: "20000" }, "https://certbeforepay.com/v1/gate");
        return new Response("", { status: 402, headers: { "PAYMENT-REQUIRED": encodePaymentRequiredHeader(pr) } });
      }
      expect(new Headers(init?.headers).get("payment-signature")).toBeTruthy();
      return new Response(JSON.stringify({ verdict: "PASS" }), { status: 200 });
    }) as typeof fetch;
    const c = new CbpClient({ paymentClient: fakePaymentClient(), fetch: fetchImpl });
    expect((await c.gate({ content: "hi" })).body).toEqual({ verdict: "PASS" });
  });

  it("gate $0.02 and peer_challenge $0.01 within the defaults; a higher price is refused unsigned", async () => {
    const cbp = fakeCbp((path) => ({ status: 200, body: { path } }));
    const pay = fakePaymentClient();
    const c = new CbpClient({ paymentClient: pay, fetch: cbp.fetch });
    expect((await c.gate({ content: "x" })).amountAtomic).toBe("20000");
    expect((await c.peerChallenge({ certificate: {} })).amountAtomic).toBe("10000");
    const dear = fakeCbp(() => ({ status: 200 }), { price: { "/v1/gate": "20001" } });
    const pay2 = fakePaymentClient();
    await expect(
      new CbpClient({ paymentClient: pay2, fetch: dear.fetch }).gate({ content: "x" }),
    ).rejects.toMatchObject({
      code: "price_too_high",
    });
    expect(pay2.signed).toHaveLength(0);
    const ok = new CbpClient({ paymentClient: pay2, fetch: dear.fetch, maxPriceAtomic: { "/v1/gate": 20001n } });
    await expect(ok.gate({ content: "x" })).resolves.toMatchObject({ status: 200 });
  });

  it("refuses a 402 whose payTo is not CertBeforePay (nothing signed)", async () => {
    const cbp = fakeCbp(() => ({ status: 200 }), { payTo: SELLER });
    const pay = fakePaymentClient();
    await expect(
      new CbpClient({ paymentClient: pay, fetch: cbp.fetch }).walletCheck({ address: SELLER }),
    ).rejects.toMatchObject({
      code: "payto_mismatch",
    });
    expect(pay.signed).toHaveLength(0);
  });

  it("refuses a non-v2 or empty 402", async () => {
    const f = (async () =>
      new Response(JSON.stringify({ x402Version: 1, accepts: [] }), { status: 402 })) as typeof fetch;
    await expect(
      new CbpClient({ paymentClient: fakePaymentClient(), fetch: f }).gate({ content: "x" }),
    ).rejects.toMatchObject({
      code: "bad_402",
    });
  });

  it("validates input before any request", async () => {
    const cbp = fakeCbp(() => ({ status: 200 }));
    const c = new CbpClient({ paymentClient: fakePaymentClient(), fetch: cbp.fetch });
    expect(() => c.walletCheck({ address: "0x12" })).toThrow(CbpError);
    expect(() => c.walletCheck({ address: SELLER, knownRecipients: ["nope"] })).toThrow(/known_recipients/);
    expect(cbp.calls).toHaveLength(0);
    expect(() => new CbpClient({} as never)).toThrow(/paymentClient/);
  });

  it("uses a custom base URL and trims the trailing slash", async () => {
    const cbp = fakeCbp(() => ({ status: 200, body: walletBody("clear") }), { base: "http://localhost:8080" });
    const c = new CbpClient({
      paymentClient: fakePaymentClient(),
      fetch: cbp.fetch,
      baseUrl: "http://localhost:8080/",
    });
    expect((await c.walletCheck({ address: SELLER })).status).toBe(200);
  });

  it("never puts the signature in an error message", async () => {
    const cbp = fakeCbp(() => ({ status: 402, body: {} }));
    const err = await new CbpClient({ paymentClient: fakePaymentClient(), fetch: cbp.fetch })
      .walletCheck({ address: SELLER })
      .catch((e) => e);
    expect(err.code).toBe("payment_failed");
    expect(String(err.message)).not.toContain(FAKE_SIGNATURE.slice(2, 20));
  });
});

describe("normalizeKnownRecipients", () => {
  it("accepts up to 50, dedupes case-insensitively, rejects bad input", () => {
    const fifty = Array.from({ length: 50 }, (_, i) => `0x${i.toString(16).padStart(40, "0")}`);
    expect(normalizeKnownRecipients(fifty)).toHaveLength(50);
    expect(normalizeKnownRecipients(undefined)).toEqual([]);
    expect(normalizeKnownRecipients([KNOWN, KNOWN.toUpperCase().replace("0X", "0x")])).toEqual([KNOWN.toLowerCase()]);
    expect(() => normalizeKnownRecipients([...fifty, KNOWN])).toThrow(/at most 50/);
    expect(() => normalizeKnownRecipients("0x" as unknown)).toThrow(/array/);
    expect(() => normalizeKnownRecipients([5])).toThrow(/0x \+ 40 hex/);
  });
});
