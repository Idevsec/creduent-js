# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- Migrated default registry URL from `api.idevsec.com` to `registry.idevsec.com`.

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
