# Creduent JS/TS SDK

[![npm version](https://img.shields.io/npm/v/@idevsec/creduent.svg?color=blue)](https://www.npmjs.com/package/@idevsec/creduent)
[![License](https://img.shields.io/github/license/idevsec/creduent-js.svg)](https://github.com/idevsec/creduent-js/blob/main/LICENSE)
[![Node Compatibility](https://img.shields.io/node/v/@idevsec/creduent.svg)](https://nodejs.org/)
[![Downloads](https://img.shields.io/npm/dm/@idevsec/creduent.svg)](https://www.npmjs.com/package/@idevsec/creduent)

The official JavaScript/TypeScript client SDK for the **Creduent Protocol** — a federated, open trust-verification layer and cryptographic identity infrastructure for autonomous AI agents.

Creduent enables autonomous agents to resolve attestation records, verify identities, and register with the Creduent registry for secure, machine-to-machine trust checks.

---

## Key Features

- 📦 **Zero Runtime Dependencies**: Extremely lightweight client library that works out-of-the-box.
- 🌐 **Native Fetch Support**: Utilizes the modern native `fetch()` API, compatible with Node.js 18+, Edge environments, and modern web browsers.
- 🏛️ **Registry Integration**: Seamless interaction with the Creduent Registry to register agents, resolve identity records, and verify active status.
- ⚙️ **Dual CJS & ESM Support**: Ships with full ESM and CommonJS exports alongside built-in TypeScript declarations.

---

## Architectural Flow

```
+------------------+             +----------------------+             +------------------+
|   Agent Domain   |             |   Creduent Registry  |             |   Agent Client   |
|   (agent.json)   |             |                      |             |    (MCP Host)    |
+------------------+             +----------------------+             +------------------+
         |                                |                                |
         |---- 1. Serve agent.json ------>|                                |
         |                                |-- 2. Verify identity & DNS --->|
         |                                |      and sign attestation      |
         |                                |                                |
         |<--- 3. Query agent endpoint ------------------------------------|  (verify_agent tool)
         |                                |                                |
         |                                |<--- 4. Fetch attestation ------|  (registry validation)
```

---

## Installation

Install the package via npm, yarn, or pnpm:

```bash
npm install @idevsec/creduent
```

---

## Quickstart

Here is how to resolve an agent's attestation record, verify their status, and register a new agent.

### ESM / TypeScript (`import`)

```typescript
import { resolveAgent, verifyAgent, registerAgent, AgentNotFoundError, CreduentError } from "@idevsec/creduent";

async function main() {
  try {
    // 1. Resolve an AI agent's attestation record
    const agentUri = "agent://creduent/reconbot";
    const record = await resolveAgent(agentUri);
    
    console.log("Agent ID:", record.agent_id);
    console.log("Issuer namespace:", record.issuer);
    console.log("Registered domain:", record.domain);
    console.log("Attestation status level:", record.level); // "verified" | "unverified" | "revoked"
    console.log("Public Key:", record.public_key);
    console.log("Registered At:", record.registered_at);
    
    // 2. Check verification directly (returns true if level is "verified")
    const isVerified = await verifyAgent(agentUri);
    console.log(`Is verified: ${isVerified}`);
    
    // 3. Register a new agent with the Creduent registry
    const registration = await registerAgent({
      agent_id: "agent://creduent/my-new-bot",
      domain: "example.com",
      agent_json_url: "https://example.com/.well-known/agent.json",
      metadata: {
        description: "A custom testing assistant"
      }
    });
    console.log("Registration successful for:", registration.agent_id);

  } catch (error) {
    if (error instanceof AgentNotFoundError) {
      console.error("Agent identity is not registered on the network.");
    } else if (error instanceof CreduentError) {
      console.error(`Registry error (${error.statusCode}):`, error.message);
    } else {
      console.error("Unexpected error:", error);
    }
  }
}

main();
```

### CommonJS (`require`)

```javascript
const { resolveAgent, verifyAgent } = require("@idevsec/creduent");

async function main() {
  const isVerified = await verifyAgent("agent://creduent/reconbot");
  console.log("Agent status is verified:", isVerified);
}

main().catch(console.error);
```

---

## API Reference

### `resolveAgent(uri, options)`
Resolves the complete attestation record for the given agent URI.

- **Parameters**:
  - `uri` (`string`): The canonical `agent://<namespace>/<path>` URI.
  - `options` (`ClientOptions`, optional): Configuration options.
- **Returns**: `Promise<AgentRecord>`

---

### `verifyAgent(uri, options)`
Helper to quickly verify if an agent has a valid, active, and `"verified"` attestation status.

- **Parameters**:
  - `uri` (`string`): The canonical `agent://` URI.
  - `options` (`ClientOptions`, optional): Configuration options.
- **Returns**: `Promise<boolean>`

---

### `registerAgent(payload, options)`
Registers an AI agent's identity with the Creduent registry.

- **Parameters**:
  - `payload` (`RegisterPayload`): Staged verification information.
    - `agent_id` (`string`): The canonical `agent://` URI.
    - `domain` (`string`): The target domain.
    - `agent_json_url` (`string`): The URL where the agent's `agent.json` metadata is hosted.
    - `metadata` (`Record<string, string>`, optional): Extra metadata fields.
  - `options` (`ClientOptions`, optional): Configuration options.
- **Returns**: `Promise<AgentRecord>`

---

## Configuration & Options (`ClientOptions`)

You can customize the client operations by passing an optional `options` parameter to any function:

```typescript
const customRecord = await resolveAgent("agent://creduent/reconbot", {
  baseUrl: "https://custom-registry.internal.net", // Override public registry domain (defaults to https://registry.idevsec.com)
  headers: {
    "Authorization": "Bearer token_123",            // Set custom authentication/authorization headers
    "X-Custom-Header": "custom-value"
  }
});
```

---

## Protocol Specification

For full information on the cryptographic standards, JCS canonicalization, and the federated verification workflows, read the complete [Creduent Protocol Specification](https://github.com/idevsec/creduent).

## License

This SDK is licensed under a Dual License model (Apache 2.0 or Commercial). See [LICENSE](LICENSE) for details.
