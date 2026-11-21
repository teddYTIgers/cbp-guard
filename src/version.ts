import { createRequire } from "node:module";

// Read from package.json so the User-Agent and --version always match the published version.
// Works from src/ (tests) and dist/ (published): package.json is one level up in both.
const pkg = createRequire(import.meta.url)("../package.json") as { version: string };

export const VERSION: string = pkg.version;
export const USER_AGENT = `cbp-guard/${VERSION}`;
