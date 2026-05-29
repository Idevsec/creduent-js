# Creduent JS/TS SDK

The official JavaScript/TypeScript client SDK for the **Creduent Protocol** — a federated, open trust-verification layer and cryptographic identity infrastructure for autonomous AI agents.

This SDK is self-contained, has **zero runtime dependencies**, supports native `fetch()` (Node 18+ and browsers), and ships with full ESM and CommonJS support alongside built-in TypeScript declarations.

---

## Installation

Install the package via npm, yarn, or pnpm:

```bash
npm install @creduent/sdk
```

---

## Quickstart

### ESM / TypeScript (`import`)

```typescript
import { resolveAgent, verifyAgent, registerAgent, AgentNotFoundError } from "@creduent/sdk";

try {
  // 1. Resolve an AI agent's attestation record
  const agentUri = "agent://creduent/reconbot";
  const record = await resolveAgent(agentUri);
  
  console.log("Agent ID:", record.agent_id);
  console.log("Issuer namespace:", record.issuer);
  console.log("Registered domain:", record.domain);
  console.log("Cryptographic level:", record.level); // "verified" | "unverified" | "revoked"
  
  // 2. Check verification directly
  const isVerified = await verifyAgent(agentUri);
  console.log(`Is verified: ${isVerified}`);
  
} catch (error) {
  if (error instanceof AgentNotFoundError) {
    console.error("Agent identity is not registered on the network.");
  } else {
    console.error("Verification error occurred:", error.message);
  }
}
```

### CommonJS (`require`)

```javascript
const { resolveAgent, verifyAgent } = require("@creduent/sdk");

async function main() {
  const isVerified = await verifyAgent("agent://creduent/reconbot");
  console.log("Agent status is verified:", isVerified);
}

main().catch(console.error);
```

---

## API Reference

### `resolveAgent(uri, options)`
Fetches the complete attestation record for the given agent URI.

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
Registers an AI agent's Ed25519 identity document with the Creduent registry.

- **Parameters**:
  - `payload` (`RegisterPayload`): Staged verification information.
  - `options` (`ClientOptions`, optional): Configuration options.
- **Returns**: `Promise<AgentRecord>`

---

## Configuration & Options (`ClientOptions`)

You can customize the client operations by passing an optional `options` parameter to any function:

```typescript
const customRecord = await resolveAgent("agent://creduent/reconbot", {
  baseUrl: "https://custom-registry.internal.net", // Override public registry domain
  headers: {
    "Authorization": "Bearer token_123",            // Set custom authentication headers
    "X-Custom-Header": "custom-value"
  }
});
```

---

## License

MIT License. See [LICENSE](LICENSE) for more details.

