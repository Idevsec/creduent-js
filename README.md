# Creduent JS/TS SDK

[![npm version](https://img.shields.io/npm/v/@idevsec/creduent.svg?color=blue)](https://www.npmjs.com/package/@idevsec/creduent)
[![License](https://img.shields.io/github/license/idevsec/creduent-js.svg)](https://github.com/idevsec/creduent-js/blob/main/LICENSE)
[![Node Compatibility](https://img.shields.io/node/v/@idevsec/creduent.svg)](https://nodejs.org/)
[![Downloads](https://img.shields.io/npm/dm/@idevsec/creduent.svg)](https://www.npmjs.com/package/@idevsec/creduent)

The official JavaScript/TypeScript SDK for the **[Creduent Protocol](https://idevsec.com/creduent)** — the open standard for cryptographic AI agent identity, Ed25519 signing, and attestation.

### What is Creduent?

**Creduent** is an open application-layer protocol for cryptographic identity and trust verification of autonomous AI agents, originally created by Kashish Kanojia and stewarded by IDevSec. The official JavaScript/TypeScript SDK is developed and maintained by IDevSec.

Performs fully **decentralized, local Ed25519 signature verification** using the Web Crypto API (`globalThis.crypto.subtle`). Zero runtime dependencies — works natively on Node.js 18+, Vercel Edge, Cloudflare Workers, Deno, and modern browsers.

> **Protocol**: [idevsec.com/creduent](https://idevsec.com/creduent) | **Docs**: [idevsec.com/creduent/docs](https://idevsec.com/creduent/docs) | **Registry**: [creduent.idevsec.com](https://creduent.idevsec.com)

---

## Key Features

- **Zero Runtime Dependencies**: No third-party cryptography libraries. Uses only the built-in Web Crypto API.
- **Edge-Compatible**: Runs anywhere `globalThis.crypto.subtle` is available — Vercel Edge, Cloudflare Workers, Deno, Node.js 18+.
- **Decentralized Verification**: Validates Ed25519 signatures locally. No registry trust required for `verify()`.
- **RFC 8785 JCS Canonicalization**: Native TypeScript implementation — deterministic JSON serialization before signing.
- **Dual CJS & ESM Support**: Ships with full ESM and CommonJS exports alongside built-in TypeScript declarations.
- **Registry Operations**: Built-in support for webhook management, attestation renewals, and authenticated capability discovery.
- **Agent Framework Integrations**: First-class adapters for Vercel AI SDK and LangGraph JS.

---

## Installation

```bash
npm install @idevsec/creduent
```

---

## Quickstart

### Verify an Agent (Decentralized)

The primary use case — fetch an agent document and validate its Ed25519 signature locally:

```typescript
import { verify } from "@idevsec/creduent";

const result = await verify("agent://idevsec/steward");

if (result.valid) {
    console.log("Agent ID:", result.agent_id);
    console.log("Owner:", result.document?.owner);
    console.log("Capabilities:", result.document?.capabilities);
} else {
    console.error("Verification failed:", result.reason);
}
```

### Verify from a Raw Document

If you already have the `agent.json` document in memory:

```typescript
import { verify } from "@idevsec/creduent";
import type { AgentDocument } from "@idevsec/creduent";

const doc: AgentDocument = {/* your agent.json object */};
const result = await verify(doc);

console.log(result.valid); // true | false
```

### Resolve a Target

Resolve an `agent://` URI, a domain, or a direct HTTPS URL to its `agent.json` document:

```typescript
import { resolveTarget } from "@idevsec/creduent";

// Resolves via registry: https://creduent.idevsec.com/attest/<uri>
const doc = await resolveTarget("agent://idevsec/steward");

// Resolves via .well-known: https://example.com/.well-known/agent.json
const doc2 = await resolveTarget("example.com");
```

### Register an Agent

```typescript
import { registerAgent } from "@idevsec/creduent";

const record = await registerAgent({
    agent_id: "agent://myorg/mybot",
    domain: "myorg.com",
    agent_json_url: "https://myorg.com/.well-known/agent.json",
    metadata: { env: "production" },
});

console.log("Registered:", record.agent_id);
```

### CommonJS

```javascript
const { verify } = require("@idevsec/creduent");

verify("agent://idevsec/steward")
    .then((result) => {
        console.log(result.valid);
    })
    .catch(console.error);
```

### Framework Integrations

#### Vercel AI SDK

Integrate agent verification as a tool within the Vercel AI SDK:

```typescript
import { creduentVerifyToolDefinition } from "@idevsec/creduent";
import { tool } from "ai"; // Vercel AI SDK

export const creduentVerifyTool = tool({
    description: creduentVerifyToolDefinition.description,
    parameters: creduentVerifyToolDefinition.parameters,
    execute: creduentVerifyToolDefinition.execute,
});
```

#### LangGraph JS

Ensure agent-to-agent interactions are secure using the LangGraph node middleware:

```typescript
import { verifyAgentNode } from "@idevsec/creduent";
import { StateGraph } from "@langchain/langgraph";

interface State {
    agentUri?: string;
    verificationResult?: any;
}

const workflow = new StateGraph<State>({
    channels: {
        agentUri: null,
        verificationResult: null,
    },
}).addNode("verify", (state) => verifyAgentNode(state, { strict: true }));
// Add other nodes and compile...
```

---

## How Verification Works

`verify()` performs a 4-step cryptographic check locally:

1. **Resolve** — Fetches the `agent.json` document from the registry or `.well-known` endpoint.
2. **Schema check** — Validates required fields (`version`, `agent_id`, `capabilities`, `signature`).
3. **Canonicalize** — Removes the `signature` field and applies RFC 8785 JCS serialization.
4. **Verify** — Validates the Ed25519 signature against all declared active public keys using `globalThis.crypto.subtle`.

If any active key produces a valid signature, the result is `valid: true`. The registry does not need to be live for step 4 to succeed.

---

## API Reference

### `verify(target)`

Performs full cryptographic verification of an agent document.

- **Parameters**:
    - `target` (`string | AgentDocument`): An `agent://` URI, domain, HTTPS URL, or a pre-fetched document object.
- **Returns**: `Promise<VerifyResult>`

---

### `resolveTarget(target)`

Resolves a target string to an `AgentDocument` without verifying the signature.

- **Parameters**:
    - `target` (`string`): `agent://` URI, domain, or HTTPS URL.
- **Returns**: `Promise<AgentDocument>`

Set the `CREDUENT_REGISTRY_URL` environment variable to override the default registry (`https://creduent.idevsec.com`).

---

### `resolveAgent(uri, options)`

Resolves the complete registry attestation record for the given agent URI.

- **Parameters**:
    - `uri` (`string`): The canonical `agent://` URI.
    - `options` (`ClientOptions`, optional): Configuration options.
- **Returns**: `Promise<AgentRecord>`

---

### `registerAgent(payload, options)`

Registers an AI agent's identity with the Creduent registry.

- **Parameters**:
    - `payload` (`RegisterPayload`): `agent_id`, `domain`, `agent_json_url`, optional `metadata`.
    - `options` (`ClientOptions`, optional): Configuration options.
- **Returns**: `Promise<AgentRecord>`

---

### `verifyAgent(uri, options)`

Checks whether an agent's attestation status is active and valid (`verified` or `trusted`). Cleanly returns `false` on HTTP 404 and HTTP 410 (revoked) instead of throwing, allowing hosts to fail-closed gracefully.

- **Parameters**:
    - `uri` (`string`): The canonical `agent://` URI.
    - `options` (`ClientOptions`, optional)
- **Returns**: `Promise<boolean>`

---

### `renewAgent(payload, options)`

Renews an agent's cryptographic registry attestation.

- **Parameters**:
    - `payload` (`RenewPayload`): Contains `agent_id`, `new_expires_at`, and signature.
    - `options` (`ClientOptions`, optional)
- **Returns**: `Promise<RenewResult>`

---

### `registerWebhook(payload, options)`

Registers a webhook URL for status change notifications.

- **Parameters**:
    - `payload` (`WebhookPayload`): Contains `agent_id`, `webhook_url`, and signature.
    - `options` (`ClientOptions`, optional)
- **Returns**: `Promise<WebhookResult>`

---

### `queryWebhook(agentId, options)`

Retrieves the currently registered webhook URL for the specified agent.

- **Parameters**:
    - `agentId` (`string`): The agent URI.
    - `options` (`ClientOptions`, optional)
- **Returns**: `Promise<WebhookResult>`

---

### `discoverAgent(targetUri, myAgentId, privateKeyPem, options)`

Performs authenticated capability discovery by querying the target agent's `/discover` endpoint with challenge-response validation.

- **Parameters**:
    - `targetUri` (`string`): Target agent URI.
    - `myAgentId` (`string`, optional): Your agent URI.
    - `privateKeyPem` (`string`, optional): Your private key PEM.
    - `options` (`ClientOptions`, optional)
- **Returns**: `Promise<DiscoveryResult>`

---

### `signPayload(payload, privateKeyPem)`

Utility to sign an arbitrary JSON payload using JCS canonicalization + Ed25519.

- **Parameters**:
    - `payload` (`any`): The payload to sign.
    - `privateKeyPem` (`string`): Private key in PEM format.
- **Returns**: `string` (Base64-encoded signature)

---

### `canonicalize(obj)`

Deterministic RFC 8785 JSON Canonicalization Scheme (JCS) serialization.

- **Returns**: `string`

```typescript
import { canonicalize } from "@idevsec/creduent";

const canonical = canonicalize({ b: 2, a: 1 });
// => '{"a":1,"b":2}'
```

---

### `verifySignature(publicKey, signature, data)`

Low-level Ed25519 signature verification using the Web Crypto API.

```typescript
import { verifySignature } from "@idevsec/creduent";

const valid = await verifySignature(
    "ed25519:V43yNaTrpqQj9YJnjYVL2HdOrqUDcnflhzNGuHTaFD8=",
    "<base64-signature>",
    "<canonical-json-string>"
);
```

---

## Types

```typescript
interface AgentDocument {
    version: string;
    agent_id?: string;
    owner?: string;
    public_key?: string;
    keys?: KeyRecord[];
    endpoint?: string;
    capabilities?: string[];
    issued_at?: string;
    signature?: string;

    // v2.0 decoupled fields
    identity?: {
        agent_id: string;
        owner: string;
        keys: KeyRecord[];
        endpoint: string;
        delegated_from?: string;
    };
    policy?: {
        capabilities: string[];
    };

    [key: string]: any;
}

interface KeyRecord {
    public_key: string;
    status: "active" | "revoked";
    expires_at?: string;
    revoked_at?: string;
}

interface VerifyResult {
    valid: boolean;
    agent_id?: string;
    reason?: string;
    document?: AgentDocument;
}

interface RegisterPayload {
    agent_id: string;
    domain: string;
    agent_json_url: string;
    metadata?: Record<string, string>;
}

interface ClientOptions {
    baseUrl?: string;
    headers?: Record<string, string>;
}

interface RenewPayload {
    agent_id: string;
    new_expires_at: string;
    signature: string;
}

interface RenewResult {
    agent_id: string;
    issuer: string;
    level: "verified" | "trusted" | "unverified" | "revoked";
    domain: string;
    public_key: string;
    registered_at: string;
    issued_at: string;
    expires_at: string;
}

interface WebhookPayload {
    agent_id: string;
    webhook_url: string;
    signature: string;
}

interface WebhookResult {
    agent_id: string;
    webhook_url: string;
}

interface DiscoveryResult {
    target_agent_id: string;
    endpoint?: string;
    capabilities?: string[];
    authenticated: boolean;
    error?: string;
}
```

---

## Environment Variables

| Variable                | Default                        | Description                                               |
| :---------------------- | :----------------------------- | :-------------------------------------------------------- |
| `CREDUENT_REGISTRY_URL` | `https://creduent.idevsec.com` | Override the registry used for `agent://` URI resolution. |

---

## Protocol Specification

- **Protocol overview**: [idevsec.com/creduent](https://idevsec.com/creduent)
- **Technical reference**: [idevsec.com/creduent/docs](https://idevsec.com/creduent/docs)
- **CLI**: [github.com/idevsec/creduent-cli](https://github.com/idevsec/creduent-cli)
- **Standards documents**: [github.com/idevsec/creduent](https://github.com/idevsec/creduent) (CREDUENT-001 through CREDUENT-006)

---

## License

Licensed under the **[Apache License 2.0](LICENSE)**. See the [LICENSE](LICENSE) file for the full legal text.
