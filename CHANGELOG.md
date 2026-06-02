# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-06-02

### Fixed
- Fixed quickstart and API parameter documentation in `README.md` for `registerAgent`, replacing the incorrect `public_key` field with the required `agent_json_url`.

## [0.1.0] - 2026-06-02

### Added
- Initial release: Core agent resolution (`resolveAgent`), status verification (`verifyAgent`), and registry registration (`registerAgent`) methods.
- Built-in TypeScript type definitions.
- CommonJS & ESM dual builds support.
