import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

const {
    signDelegation,
    verifyDelegationChain,
    signPopHeader,
    verifyPopHeader,
} = await import("../dist/esm/delegation.js");

function makeKeypair() {
    const pair = generateKeyPairSync("ed25519");
    const pem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const der = pair.publicKey.export({ type: "spki", format: "der" });
    const raw = der.slice(der.length - 32);
    const pubStr = `ed25519:${raw.toString("base64")}`;
    return { pem, pubStr };
}

describe("CDT Delegation & Proof-of-Possession (CREDUENT-007)", () => {
    test("signDelegation generates valid CDT and verifyDelegationChain verifies single hop", async () => {
        const root = makeKeypair();
        const child = makeKeypair();

        const cdt = signDelegation({
            delegatorPrivateKeyPem: root.pem,
            delegatorUri: "agent://corp/parent",
            delegateUri: "agent://corp/child",
            delegatePublicKey: child.pubStr,
            constraints: {
                allowed_capabilities: ["scan", "query"],
                max_reversibility: "reversible",
                allowed_tools: ["search", "fetch"],
            },
            intentHash: "sha256:abc123456",
            ttlSeconds: 1800,
        });

        assert.equal(cdt.version, "1.0");
        assert.equal(cdt.delegator, "agent://corp/parent");
        assert.equal(cdt.delegate, "agent://corp/child");
        assert.equal(cdt.delegate_public_key, child.pubStr);
        assert.ok(typeof cdt.signature === "string");

        const res = await verifyDelegationChain({
            cdtChain: [cdt],
            trustedPublicKeys: { "agent://corp/parent": root.pubStr },
        });

        assert.equal(res.valid, true);
        assert.equal(res.chainDepth, 1);
        assert.equal(res.rootDelegator, "agent://corp/parent");
        assert.equal(res.leafDelegate, "agent://corp/child");
    });

    test("tampered CDT fails with CDT_SIGNATURE_INVALID", async () => {
        const root = makeKeypair();
        const child = makeKeypair();

        const cdt = signDelegation({
            delegatorPrivateKeyPem: root.pem,
            delegatorUri: "agent://corp/parent",
            delegateUri: "agent://corp/child",
            delegatePublicKey: child.pubStr,
            constraints: { allowed_capabilities: ["scan"] },
        });

        cdt.constraints = { allowed_capabilities: ["scan", "admin_root"] };

        const res = await verifyDelegationChain({
            cdtChain: [cdt],
            trustedPublicKeys: { "agent://corp/parent": root.pubStr },
        });

        assert.equal(res.valid, false);
        assert.equal(res.errorCode, "CDT_SIGNATURE_INVALID");
    });

    test("Proof-of-Possession header signing and verification", async () => {
        const child = makeKeypair();
        const tokenId = "urn:uuid:12345678-1234-5678-1234-567812345678";

        const { popSignature, timestamp } = signPopHeader({
            delegatePrivateKeyPem: child.pem,
            httpMethod: "POST",
            uriPath: "/api/v1/tools/search",
            tokenId,
        });

        const ok = await verifyPopHeader({
            popSignature,
            timestamp,
            delegatePublicKey: child.pubStr,
            httpMethod: "POST",
            uriPath: "/api/v1/tools/search",
            tokenId,
        });
        assert.equal(ok, true);

        // Mismatched path fails
        const badPath = await verifyPopHeader({
            popSignature,
            timestamp,
            delegatePublicKey: child.pubStr,
            httpMethod: "POST",
            uriPath: "/api/v1/tools/delete",
            tokenId,
        });
        assert.equal(badPath, false);

        // Expired timestamp fails
        const oldTimestamp = new Date(Date.now() - 120 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
        const expired = await verifyPopHeader({
            popSignature,
            timestamp: oldTimestamp,
            delegatePublicKey: child.pubStr,
            httpMethod: "POST",
            uriPath: "/api/v1/tools/search",
            tokenId,
            maxSkewSeconds: 60,
        });
        assert.equal(expired, false);
    });

    test("multi-hop delegation chain with PoP verification", async () => {
        const root = makeKeypair();
        const mid = makeKeypair();
        const leaf = makeKeypair();

        // Hop 1: Root -> Mid
        const cdt1 = signDelegation({
            delegatorPrivateKeyPem: root.pem,
            delegatorUri: "agent://corp/root",
            delegateUri: "agent://corp/mid",
            delegatePublicKey: mid.pubStr,
            constraints: {
                allowed_capabilities: ["read", "write"],
                max_reversibility: "reversible",
                allowed_tools: ["db_read", "db_write"],
            },
        });

        // Hop 2: Mid -> Leaf (narrowed)
        const cdt2 = signDelegation({
            delegatorPrivateKeyPem: mid.pem,
            delegatorUri: "agent://corp/mid",
            delegateUri: "agent://corp/leaf",
            delegatePublicKey: leaf.pubStr,
            constraints: {
                allowed_capabilities: ["read"],
                max_reversibility: "read-only",
                allowed_tools: ["db_read"],
            },
        });

        const { popSignature, timestamp } = signPopHeader({
            delegatePrivateKeyPem: leaf.pem,
            httpMethod: "GET",
            uriPath: "/data",
            tokenId: cdt2.token_id,
        });

        const res = await verifyDelegationChain({
            cdtChain: [cdt1, cdt2],
            targetAction: "db_read",
            requiredCapability: "read",
            popSignature,
            popTimestamp: timestamp,
            httpMethod: "GET",
            uriPath: "/data",
            trustedPublicKeys: { "agent://corp/root": root.pubStr },
        });

        assert.equal(res.valid, true);
        assert.equal(res.chainDepth, 2);
        assert.equal(res.rootDelegator, "agent://corp/root");
        assert.equal(res.leafDelegate, "agent://corp/leaf");
    });

    test("privilege escalation detection rejects expanded capabilities", async () => {
        const root = makeKeypair();
        const mid = makeKeypair();
        const leaf = makeKeypair();

        const cdt1 = signDelegation({
            delegatorPrivateKeyPem: root.pem,
            delegatorUri: "agent://corp/root",
            delegateUri: "agent://corp/mid",
            delegatePublicKey: mid.pubStr,
            constraints: { allowed_capabilities: ["read"] },
        });

        // Mid tries to expand capabilities to include "write"
        const cdt2 = signDelegation({
            delegatorPrivateKeyPem: mid.pem,
            delegatorUri: "agent://corp/mid",
            delegateUri: "agent://corp/leaf",
            delegatePublicKey: leaf.pubStr,
            constraints: { allowed_capabilities: ["read", "write"] },
        });

        const res = await verifyDelegationChain({
            cdtChain: [cdt1, cdt2],
            trustedPublicKeys: { "agent://corp/root": root.pubStr },
        });

        assert.equal(res.valid, false);
        assert.equal(res.errorCode, "CDT_PRIVILEGE_ESCALATION");
    });

    test("chain depth exceeded (> 8) rejects with CDT_CHAIN_DEPTH_EXCEEDED", async () => {
        const root = makeKeypair();
        const chain = [];
        let curr = root;
        let currUri = "agent://corp/agent0";

        for (let i = 1; i <= 9; i++) {
            const next = makeKeypair();
            const nextUri = `agent://corp/agent${i}`;
            const cdt = signDelegation({
                delegatorPrivateKeyPem: curr.pem,
                delegatorUri: currUri,
                delegateUri: nextUri,
                delegatePublicKey: next.pubStr,
                constraints: { allowed_capabilities: ["scan"] },
            });
            chain.push(cdt);
            curr = next;
            currUri = nextUri;
        }

        const res = await verifyDelegationChain({
            cdtChain: chain,
            maxChainDepth: 8,
            trustedPublicKeys: { "agent://corp/agent0": root.pubStr },
        });

        assert.equal(res.valid, false);
        assert.equal(res.errorCode, "CDT_CHAIN_DEPTH_EXCEEDED");
    });

    test("action constraint enforcement rejects unlisted tool", async () => {
        const root = makeKeypair();
        const child = makeKeypair();

        const cdt = signDelegation({
            delegatorPrivateKeyPem: root.pem,
            delegatorUri: "agent://corp/root",
            delegateUri: "agent://corp/child",
            delegatePublicKey: child.pubStr,
            constraints: {
                allowed_capabilities: ["query"],
                allowed_tools: ["safe_search"],
            },
        });

        const ok = await verifyDelegationChain({
            cdtChain: [cdt],
            targetAction: "safe_search",
            trustedPublicKeys: { "agent://corp/root": root.pubStr },
        });
        assert.equal(ok.valid, true);

        const denied = await verifyDelegationChain({
            cdtChain: [cdt],
            targetAction: "unauthorized_drop",
            trustedPublicKeys: { "agent://corp/root": root.pubStr },
        });
        assert.equal(denied.valid, false);
        assert.equal(denied.errorCode, "CDT_CONSTRAINT_VIOLATION");
    });
});

