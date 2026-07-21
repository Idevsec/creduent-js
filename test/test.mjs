/**
 * creduent-js SDK Test Suite
 * Uses Node.js built-in test runner (node:test) — no external deps required.
 * Run: node --test test/test.mjs
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, createPrivateKey, createHmac } from "node:crypto";

// ──────────────────────────────────────────────────────────────────────────────
// Helpers — Ed25519 keygen + sign (Node.js native)
// ──────────────────────────────────────────────────────────────────────────────

function generateEd25519Pair() {
    return generateKeyPairSync("ed25519");
}

function rawPublicKeyBase64(publicKey) {
    // Export as DER SubjectPublicKeyInfo, last 32 bytes are the raw key
    const der = publicKey.export({ type: "spki", format: "der" });
    const raw = der.slice(der.length - 32);
    return raw.toString("base64");
}

function signData(privateKey, data) {
    const bytes = Buffer.from(data, "utf-8");
    return sign(null, bytes, privateKey).toString("base64");
}

// ──────────────────────────────────────────────────────────────────────────────
// Import SDK modules (ESM build)
// ──────────────────────────────────────────────────────────────────────────────

const { canonicalize } = await import("../dist/esm/crypto.js");
const { verifySignature, verifyWebhookSignature } = await import("../dist/esm/crypto.js");
const { verify } = await import("../dist/esm/verify.js");
const { verifyAgent, resolveAgent } = await import("../dist/esm/client.js");

// ──────────────────────────────────────────────────────────────────────────────
// 1. canonicalize (JCS / RFC 8785)
// ──────────────────────────────────────────────────────────────────────────────

describe("canonicalize (JCS)", () => {
    test("sorts keys lexicographically", () => {
        const result = canonicalize({ z: 1, a: 2, m: 3 });
        assert.equal(result, '{"a":2,"m":3,"z":1}');
    });

    test("handles nested objects recursively", () => {
        const result = canonicalize({ b: { d: 4, c: 3 }, a: 1 });
        assert.equal(result, '{"a":1,"b":{"c":3,"d":4}}');
    });

    test("handles arrays (preserving order)", () => {
        const result = canonicalize({ keys: ["z", "a", "m"] });
        assert.equal(result, '{"keys":["z","a","m"]}');
    });

    test("handles null values", () => {
        assert.equal(canonicalize(null), "null");
    });

    test("skips undefined values", () => {
        const result = canonicalize({ a: 1, b: undefined });
        assert.equal(result, '{"a":1}');
    });

    test("is deterministic — same output for same input twice", () => {
        const obj = { z: 99, a: "hello", m: [1, 2, 3] };
        assert.equal(canonicalize(obj), canonicalize(obj));
    });

    test("different key ordering produces same canonical form", () => {
        const a = { z: 1, a: 2 };
        const b = { a: 2, z: 1 };
        assert.equal(canonicalize(a), canonicalize(b));
    });
});

// ──────────────────────────────────────────────────────────────────────────────
// 2. verifySignature (Ed25519 Web Crypto)
// ──────────────────────────────────────────────────────────────────────────────

describe("verifySignature", () => {
    test("valid signature returns true", async () => {
        const { privateKey, publicKey } = generateEd25519Pair();
        const raw64 = rawPublicKeyBase64(publicKey);
        const publicKeyStr = `ed25519:${raw64}`;

        const data = '{"agent_id":"agent://test/agent","version":"1.0"}';
        const sigB64 = signData(privateKey, data);

        const result = await verifySignature(publicKeyStr, sigB64, data);
        assert.equal(result, true);
    });

    test("tampered payload returns false", async () => {
        const { privateKey, publicKey } = generateEd25519Pair();
        const raw64 = rawPublicKeyBase64(publicKey);
        const publicKeyStr = `ed25519:${raw64}`;

        const data = '{"agent_id":"agent://test/agent","version":"1.0"}';
        const sigB64 = signData(privateKey, data);

        const tamperedData = '{"agent_id":"agent://test/evil","version":"1.0"}';
        const result = await verifySignature(publicKeyStr, sigB64, tamperedData);
        assert.equal(result, false);
    });

    test("wrong key returns false", async () => {
        const { privateKey } = generateEd25519Pair();
        const { publicKey: wrongPublicKey } = generateEd25519Pair();

        const raw64 = rawPublicKeyBase64(wrongPublicKey);
        const publicKeyStr = `ed25519:${raw64}`;

        const data = '{"agent_id":"agent://test/agent","version":"1.0"}';
        const sigB64 = signData(privateKey, data);

        const result = await verifySignature(publicKeyStr, sigB64, data);
        assert.equal(result, false);
    });

    test("invalid base64 signature returns false", async () => {
        const { publicKey } = generateEd25519Pair();
        const raw64 = rawPublicKeyBase64(publicKey);
        const publicKeyStr = `ed25519:${raw64}`;

        const result = await verifySignature(publicKeyStr, "!!!not_valid_base64!!!", "data");
        assert.equal(result, false);
    });

    test("missing ed25519: prefix returns false", async () => {
        const { privateKey, publicKey } = generateEd25519Pair();
        const raw64 = rawPublicKeyBase64(publicKey);
        const data = "test";
        const sigB64 = signData(privateKey, data);

        // No prefix
        const result = await verifySignature(raw64, sigB64, data);
        assert.equal(result, false);
    });
});

// ──────────────────────────────────────────────────────────────────────────────
// 3. verify() — local cryptographic verification of AgentDocument
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Builds a signed v1.1 agent document using a freshly generated keypair.
 */
function buildSignedV1Doc(overrides = {}) {
    const { privateKey, publicKey } = generateEd25519Pair();
    const raw64 = rawPublicKeyBase64(publicKey);
    const publicKeyStr = `ed25519:${raw64}`;

    const doc = {
        version: "1.1",
        agent_id: "agent://test/myagent",
        owner: "Test Corp",
        public_key: publicKeyStr,
        capabilities: ["task_execution"],
        issued_at: new Date().toISOString(),
        ...overrides,
    };

    // Canonicalize and sign
    const canonical = canonicalize(doc);
    const sigB64 = signData(privateKey, canonical);

    return { doc: { ...doc, signature: sigB64 }, privateKey, publicKeyStr };
}

/**
 * Builds a signed v2.0 agent document.
 */
function buildSignedV2Doc(overrides = {}) {
    const { privateKey, publicKey } = generateEd25519Pair();
    const raw64 = rawPublicKeyBase64(publicKey);
    const publicKeyStr = `ed25519:${raw64}`;

    const doc = {
        version: "2.0",
        identity: {
            agent_id: "agent://test/myagent",
            owner: "Test Corp",
            keys: [{ public_key: publicKeyStr, status: "active" }],
            endpoint: "https://test.example.com",
        },
        policy: {
            capabilities: ["task_execution"],
        },
        issued_at: new Date().toISOString(),
        ...overrides,
    };

    const canonical = canonicalize(doc);
    const sigB64 = signData(privateKey, canonical);

    return { doc: { ...doc, signature: sigB64 }, privateKey, publicKeyStr };
}

describe("verify() — v1.1 documents", () => {
    test("valid v1.1 document passes verification", async () => {
        const { doc } = buildSignedV1Doc();
        const result = await verify(doc);
        assert.equal(result.valid, true);
        assert.equal(result.agent_id, "agent://test/myagent");
    });

    test("missing signature returns invalid", async () => {
        const { doc } = buildSignedV1Doc();
        delete doc.signature;
        const result = await verify(doc);
        assert.equal(result.valid, false);
        assert.match(result.reason, /No signature/i);
    });

    test("tampered field returns invalid", async () => {
        const { doc } = buildSignedV1Doc();
        doc.owner = "Evil Corp"; // tamper after signing
        const result = await verify(doc);
        assert.equal(result.valid, false);
        assert.match(result.reason, /Signature verification failed/i);
    });

    test("missing required fields returns invalid schema", async () => {
        const doc = { version: "1.1", agent_id: "agent://x/y" }; // no capabilities
        const result = await verify(doc);
        assert.equal(result.valid, false);
        assert.match(result.reason, /Invalid schema/i);
    });
});

describe("verify() — v2.0 documents", () => {
    test("valid v2.0 document passes verification", async () => {
        const { doc } = buildSignedV2Doc();
        const result = await verify(doc);
        assert.equal(result.valid, true);
        assert.equal(result.agent_id, "agent://test/myagent");
    });

    test("missing identity/policy returns invalid", async () => {
        const { doc } = buildSignedV2Doc();
        delete doc.identity;
        const result = await verify(doc);
        assert.equal(result.valid, false);
        assert.match(result.reason, /identity and policy/i);
    });

    test("all keys revoked returns invalid", async () => {
        const { doc } = buildSignedV2Doc();
        // Mark the only key as revoked
        doc.identity.keys[0].status = "revoked";
        const result = await verify(doc);
        assert.equal(result.valid, false);
        assert.match(result.reason, /No active public keys/i);
    });

    test("tampered field returns invalid", async () => {
        const { doc } = buildSignedV2Doc();
        doc.identity.owner = "Evil Corp"; // tamper after signing
        const result = await verify(doc);
        assert.equal(result.valid, false);
        assert.match(result.reason, /Signature verification failed/i);
    });
});

// ──────────────────────────────────────────────────────────────────────────────
// 4. verifyAgent / resolveAgent — with mocked fetch
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Replaces globalThis.fetch temporarily for a single test.
 */
function withMockedFetch(mockFn, fn) {
    const original = globalThis.fetch;
    globalThis.fetch = mockFn;
    try {
        return fn();
    } finally {
        globalThis.fetch = original;
    }
}

describe("resolveAgent / verifyAgent (mocked fetch)", () => {
    test("resolveAgent returns parsed attestation record on 200", async () => {
        const mockRecord = {
            agent_id: "agent://idevsec/steward",
            issuer: "agent://creduent/registry",
            level: "verified",
            domain: "idevsec.com",
            public_key: "ed25519:abc",
            registered_at: new Date().toISOString(),
            issued_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + 86400000 * 30).toISOString(),
        };

        const record = await withMockedFetch(
            async (_url, _opts) => ({
                ok: true,
                status: 200,
                statusText: "OK",
                text: async () => JSON.stringify(mockRecord),
            }),
            () => resolveAgent("agent://idevsec/steward", { baseUrl: "https://creduent.idevsec.com" })
        );

        assert.equal(record.agent_id, "agent://idevsec/steward");
        assert.equal(record.level, "verified");
    });

    test("resolveAgent throws AgentNotFoundError on 404", async () => {
        await assert.rejects(
            () =>
                withMockedFetch(
                    async () => ({ ok: false, status: 404, statusText: "Not Found", text: async () => "" }),
                    () => resolveAgent("agent://test/nonexistent")
                ),
            (err) => {
                assert.equal(err.name, "AgentNotFoundError");
                return true;
            }
        );
    });

    test("verifyAgent returns true for verified level", async () => {
        const mockRecord = { level: "verified" };
        const result = await withMockedFetch(
            async () => ({ ok: true, status: 200, statusText: "OK", text: async () => JSON.stringify(mockRecord) }),
            () => verifyAgent("agent://idevsec/steward")
        );
        assert.equal(result, true);
    });

    test("verifyAgent returns true for trusted level", async () => {
        const mockRecord = { level: "trusted" };
        const result = await withMockedFetch(
            async () => ({ ok: true, status: 200, statusText: "OK", text: async () => JSON.stringify(mockRecord) }),
            () => verifyAgent("agent://idevsec/steward")
        );
        assert.equal(result, true);
    });

    test("verifyAgent returns false for unverified level", async () => {
        const mockRecord = { level: "unverified" };
        const result = await withMockedFetch(
            async () => ({ ok: true, status: 200, statusText: "OK", text: async () => JSON.stringify(mockRecord) }),
            () => verifyAgent("agent://test/agent")
        );
        assert.equal(result, false);
    });

    test("verifyAgent returns false for 404 (agent not registered)", async () => {
        const result = await withMockedFetch(
            async () => ({ ok: false, status: 404, statusText: "Not Found", text: async () => "" }),
            () => verifyAgent("agent://test/nonexistent")
        );
        assert.equal(result, false);
    });

    test("verifyAgent returns false for revoked (410 Gone)", async () => {
        const result = await withMockedFetch(
            async () => ({
                ok: false,
                status: 410,
                statusText: "Gone",
                text: async () => '{"detail":"agent is revoked"}',
            }),
            () => verifyAgent("agent://test/revoked-agent")
        );
        assert.equal(result, false);
    });
});

// ──────────────────────────────────────────────────────────────────────────────
// 5. verifyWebhookSignature (HMAC-SHA256 Webhook Verification)
// ──────────────────────────────────────────────────────────────────────────────

describe("verifyWebhookSignature", () => {
    test("valid HMAC signature returns true", async () => {
        const secret = "whsec_test_secret_key_123456";
        const timestamp = "1784594000";
        const payload = {
            event: "agent.expiry_warning",
            agent_id: "agent://test/agent",
            days_remaining: 28,
        };

        const canonical = canonicalize(payload);
        const sigData = timestamp + "." + canonical;
        const expectedSig = createHmac("sha256", secret).update(sigData).digest("hex");

        const result = await verifyWebhookSignature(secret, expectedSig, timestamp, payload);
        assert.equal(result, true);
    });

    test("invalid signature returns false", async () => {
        const secret = "whsec_test_secret_key_123456";
        const timestamp = "1784594000";
        const payload = {
            event: "agent.expiry_warning",
            agent_id: "agent://test/agent",
        };

        const result = await verifyWebhookSignature(secret, "bad_sig_hex", timestamp, payload);
        assert.equal(result, false);
    });

    test("tampered payload returns false", async () => {
        const secret = "whsec_test_secret_key_123456";
        const timestamp = "1784594000";
        const payload = {
            event: "agent.expiry_warning",
            agent_id: "agent://test/agent",
        };

        const canonical = canonicalize(payload);
        const sigData = timestamp + "." + canonical;
        const expectedSig = createHmac("sha256", secret).update(sigData).digest("hex");

        const tamperedPayload = {
            event: "agent.expiry_warning",
            agent_id: "agent://test/attacker",
        };

        const result = await verifyWebhookSignature(secret, expectedSig, timestamp, tamperedPayload);
        assert.equal(result, false);
    });
});

