# Releasing cbp-guard (maintainers)

This file is not part of the npm package (see `files` in `package.json`).

## How a release is published

`.github/workflows/publish.yml` publishes with npm **trusted publishing** (GitHub OIDC, `npm publish --provenance --access public`). There is no npm token anywhere. It never runs on a push to `main`; it runs only from a `v*.*.*` tag or a manual dispatch (with the confirmation phrase), and the tag must match the `package.json` version.

The job runs in the protected environment `npm-publish`. Each run waits for approval by the environment's required reviewer; the confirmation phrase is not an approval control.

## Required repository and npm settings

- **Required:** environment `npm-publish` (Settings → Environments) with required reviewer `teddYTIgers` and a deployment rule that allows only tags matching `v*.*.*`. Without it, anyone with write access to the repo could publish by pushing a tag.
- npmjs.com trusted publisher for package `cbp-guard` (account `teddytigers`, 2FA on): repository `teddYTIgers/cbp-guard`, workflow `publish.yml`, environment `npm-publish`.

## Release steps

1. Bump the version in `package.json`, `package-lock.json` (two places) and `server.json` (two places) in a pull request; CI must be green.
2. After merge, tag the merge commit `vX.Y.Z` and push the tag; approve the `npm-publish` deployment.
3. MCP Registry: publish the same version from `server.json` with `mcp-publisher` (`mcp-publisher login github`, then `mcp-publisher publish`) after the npm version exists.
4. npm versions are permanent (unpublish is limited); check the README and `server.json` before tagging.
