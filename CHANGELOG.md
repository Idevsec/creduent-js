# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),

## [2.0.8] - 2026-07-21

### Added
- **HMAC Webhook Verification**: Added `verifyWebhookSignature(secret, signatureHex, timestamp, payload)` function to `src/crypto.ts` (exported from the package root). Uses standard Web Crypto APIs for timing-safe signature verification.
- **Contributing Guidelines**: Added Project Roadmap & Wanted Features hotspots section to `CONTRIBUTING.md`.

## [2.0.7] - 2026-07-10

### Security
- **SSRF Guard in `discoverAgent()`**: Added HTTPS-only scheme validation before the outbound `fetch()` call in `discoverAgent()`. If the endpoint URL from an agent document uses any scheme other than `https:` (e.g. `http:`, `file:`), the function now returns an unauthenticated result with a clear error message instead of making the request. Prevents SSRF in Node.js server-side environments where a malicious agent document could point the endpoint field at an internal service or metadata API.

## [2.0.6] - 2026-07-09

### Changed
- **Authorship Alignment**: Updated SDK readme to reflect that the Creduent Protocol was originally created by Kashish Kanojia and is stewarded by IDevSec.

## [2.0.5] - 2026-07-05

### Changed

- **Documentation & Tests:** Replaced the legacy test agent (`agent://creduent/reconbot`) with the official standard agent (`agent://idevsec/steward`) across all code snippets, examples, and CLI help text to ensure consistency with production environments.
- **CLI References:** Purged internal testing stubs from CLI usage output.

## [2.0.4] - 2026-07-04

### Fixed

- **NPM Lockfile Registry Resolvers:** Replaced relative local directory links (`../../creduent-cli`) in `package-lock.json` with direct public registry pointers.
- **Removed Self-Dependency:** Cleaned up `package.json` dependencies by removing the package's self-import entry (`@idevsec/creduent`) which was causing circular resolution conflicts.
- **TypeScript 6 Compatibility:** Configured explicit `"types": ["node"]` compiler definitions in `tsconfig.json` to resolve Node.js glob import warnings.
- **Workflow Build Steps:** Enabled `--legacy-peer-deps` to bypass strict local package locks in CI runners, and removed execution of the missing `npm run test` script.

### Added

- **Community Standards & Styling:** Integrated `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CONTRIBUTING.md`, `.editorconfig`, `.prettierrc`, and `.pre-commit-config.yaml`.
- **CI Workflows:** Added automated Prettier styling checks and publication actions.

## [2.0.3] - 2026-06-29

### Changed

- Maintenance update bump.

## [2.0.2] - 2026-06-27

### Changed

- **Unified Domain Name Migration:** Standardized default registry URL on `creduent.idevsec.com` across all SDK methods, default arguments, and environment configurations.

## [2.0.1] - 2026-06-27

### Changed

- **Single Licensing Alignment:** Transitioned package metadata to sole coverage under the Apache License 2.0.

## [2.0.0] - 2026-06-23

### Added

- **v2.0 Schema Split Support**: Added dynamic parsing and version-gating for the v2.0 schema structure separating `identity`, `policy`, and `signature` blocks.
- **DNS Recovery Override Endpoint Support**: Updated client resolver to support recovery overrides.
- **Multisig Quorum Authorization Support**: Implemented threshold signature verification client support.
- **Expiry Enforcements**: Synced verification pipeline to handle the shortened 30-day attestation windows.

### Fixed

- **HTTP 410 Revoked Response Handling**: Fixed `verifyAgent` to cleanly catch HTTP 410 (revoked) registry status codes and return `false` instead of throwing a raw `CreduentError` (preventing integrators from crashing).

## [0.1.3] - 2026-06-13

### Changed

- Migrated default registry URL from `api.idevsec.com` to `creduent.idevsec.com`.

## [0.1.2] - 2026-06-08

### Changed

- Standardized git ignores.
- Re-packaged distribution package.

## [0.1.1] - 2026-06-02

### Fixed

- Fixed quickstart and API parameter documentation in `README.md` for `registerAgent`, replacing the incorrect `public_key` field with the required `agent_json_url`.

## [0.1.0] - 2026-06-02

### Added

- Initial release: Core agent resolution (`resolveAgent`), status verification (`verifyAgent`), and registry registration (`registerAgent`) methods.
- Built-in TypeScript type definitions.
- CommonJS & ESM dual builds support.
