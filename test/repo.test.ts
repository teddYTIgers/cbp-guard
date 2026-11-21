import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { describe, expect, it } from "vitest";
import { VERSION } from "../src/version.js";

const ROOT = join(import.meta.dirname, "..");
const read = (p: string) => readFileSync(join(ROOT, p), "utf8");
const pkg = JSON.parse(read("package.json"));
const server = JSON.parse(read("server.json"));

function tracked(): string[] {
  return execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard"], {
    cwd: ROOT,
    encoding: "utf8",
  })
    .split("\n")
    .filter(Boolean);
}

describe("package.json and server.json", () => {
  it("name, license, mcpName, bin, repository and homepage", () => {
    expect(pkg.name).toBe("cbp-guard");
    expect(pkg.license).toBe("MIT");
    expect(pkg.mcpName).toBe("io.github.teddYTIgers/certbeforepay");
    expect(pkg.bin).toEqual({ "cbp-guard": "dist/cli.js" });
    expect(pkg.repository.url).toBe("git+https://github.com/teddYTIgers/cbp-guard.git");
    expect(pkg.homepage).toBe("https://certbeforepay.com");
    expect(pkg.version).toBe(VERSION);
  });

  it("server.json matches package.json and lists the npm stdio package (not a remote)", () => {
    expect(server.name).toBe(pkg.mcpName);
    expect(server.version).toBe(pkg.version);
    expect(server.remotes).toBeUndefined();
    expect(server.packages).toHaveLength(1);
    const p = server.packages[0];
    expect(p).toMatchObject({
      registryType: "npm",
      identifier: "cbp-guard",
      version: pkg.version,
      transport: { type: "stdio" },
    });
    expect(p.packageArguments).toEqual([{ type: "positional", value: "mcp" }]);
    expect(p.environmentVariables[0]).toMatchObject({
      name: "CBP_GUARD_PRIVATE_KEY",
      isRequired: true,
      isSecret: true,
    });
  });

  it("server.json validates against the MCP Registry schema 2025-12-11", () => {
    const schema = JSON.parse(read("test/fixtures/server.schema.2025-12-11.json"));
    expect(server.$schema).toBe("https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json");
    const ajv = new Ajv.default({ strict: false, allErrors: true });
    addFormats.default(ajv);
    const validate = ajv.compile(schema);
    expect(validate(server), JSON.stringify(validate.errors)).toBe(true);
  });

  it("x402 dependencies are v2 (no legacy v1 packages)", () => {
    const all = { ...pkg.dependencies, ...pkg.peerDependencies, ...pkg.devDependencies };
    for (const name of ["x402", "x402-fetch", "x402-axios"]) expect(all).not.toHaveProperty(name);
    for (const name of ["@x402/core", "@x402/evm"]) expect(pkg.dependencies[name]).toMatch(/^\^2\./);
  });
});

describe("customer copy (OWNER-COPY)", () => {
  it("README has no internal release, owner, bot or approval notes", () => {
    const readme = read("README.md");
    for (const bad of [/not published/i, /owner/i, /\bbots?\b/i, /\bapprov(e|ed|al)\b/i, /not done yet/i, /remaining steps/i])
      expect(readme).not.toMatch(bad);
    expect(readme).toContain("npm install cbp-guard");
    expect(readme).toContain("npx cbp-guard mcp");
  });

  it("README first line and server.json description are the drafted strings", () => {
    const first = read("README.md")
      .split("\n")
      .filter((l) => l.trim() && !l.startsWith("#"))[0];
    expect(first).toBe(
      "cbp-guard checks the wallet your AI agent is about to pay, before it signs, and stops payments to known scam or lookalike wallets. Each wallet check is $0.01 in USDC on Base via x402.",
    );
    expect(server.description).toBe(
      "Check an x402 payTo for scam/phishing and address-poisoning lookalikes before paying. $0.01/check.",
    );
  });

  it("no free-quota or $0.05 wallet-check claims, no signed-answer claim", () => {
    const text = `${read("README.md")}\n${read("server.json")}`.toLowerCase();
    for (const bad of ["3 free", "free a day", "free daily", "$0.05", "ed25519", "signed answer"])
      expect(text).not.toContain(bad);
  });
});

describe("publish workflow", () => {
  const wf = read(".github/workflows/publish.yml");
  const on = wf.slice(wf.indexOf("\non:"), wf.indexOf("\npermissions:"));

  it("never runs on push to a branch (dispatch or v* tag only)", () => {
    expect(on).toContain("workflow_dispatch");
    expect(on).not.toMatch(/branches/);
    expect(on).not.toMatch(/pull_request/);
    expect(on).toMatch(/tags:\s*\n\s*- "v\*\.\*\.\*"/);
  });

  it("uses npm trusted publishing: id-token write, --provenance, no NPM_TOKEN", () => {
    expect(wf).toContain("id-token: write");
    expect(wf).toContain("npm publish --provenance");
    const code = wf
      .split("\n")
      .filter((l) => !l.trim().startsWith("#"))
      .join("\n");
    expect(code).not.toMatch(/NPM_TOKEN|NODE_AUTH_TOKEN|secrets\./);
  });

  it("CI workflows never publish", () => {
    for (const f of ["ci.yml", "secrets.yml"]) {
      const t = read(`.github/workflows/${f}`);
      expect(t).not.toMatch(/npm publish|id-token/);
    }
  });

  it("every action is pinned to a full commit SHA", () => {
    for (const f of ["ci.yml", "secrets.yml", "publish.yml"]) {
      for (const m of read(`.github/workflows/${f}`).matchAll(/uses:\s*(\S+)/g)) {
        expect(m[1]).toMatch(/@[0-9a-f]{40}$/);
      }
    }
  });
});

describe("tree hygiene", () => {
  it("no .env files, keys or scam-list data are tracked", () => {
    for (const f of tracked()) {
      expect(f).not.toMatch(/(^|\/)\.env(\.|$)|\.pem$|\.key$|scam|denylist|scamsniffer/i);
    }
  });

  it("no hard-coded private key in source or tests (keys are generated at run time)", () => {
    for (const f of tracked().filter((p) => /\.(ts|js|json|ya?ml|md)$/.test(p) && !p.startsWith("test/fixtures/"))) {
      if (f === "package-lock.json") continue;
      expect(read(f), f).not.toMatch(/0x[0-9a-fA-F]{64}(?![0-9a-fA-F])/);
    }
  });
});
