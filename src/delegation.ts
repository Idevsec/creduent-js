import { createPrivateKey, sign } from "crypto";
import { canonicalize, verifySignature } from "./crypto.js";

export interface DelegationVerifyResult {
    valid: boolean;
    error?: string;
    errorCode?: string;
    chainDepth: number;
    rootDelegator?: string;
    leafDelegate?: string;
    allowedCapabilities?: string[];
    allowedTools?: string[];
    maxReversibility?: string;
}

const REVERSIBILITY_ORDER: Record<string, number> = {
    "read-only": 0,
    "reversible": 1,
    "external-reversible": 2,
    "irreversible": 3,
};

/**
 * Constructs, JCS-canonicalizes, and signs a Creduent Delegation Token (CDT).
 * Compliant with CREDUENT-007 Section 3 and Section 6.1.
 */
export function signDelegation(params: {
    delegatorPrivateKeyPem: string;
    delegatorUri: string;
    delegateUri: string;
    delegatePublicKey: string;
    constraints: Record<string, unknown>;
    intentHash?: string;
    ttlSeconds?: number;
    tokenId?: string;
    issuedAt?: string;
}): Record<string, unknown> {
    const {
        delegatorPrivateKeyPem,
        delegatorUri,
        delegateUri,
        delegatePublicKey,
        constraints,
        intentHash,
        ttlSeconds = 3600,
        tokenId,
        issuedAt,
    } = params;

    if (!delegatorUri?.startsWith("agent://")) {
        throw new Error("delegatorUri must be a valid 'agent://' URI");
    }
    if (!delegateUri?.startsWith("agent://")) {
        throw new Error("delegateUri must be a valid 'agent://' URI");
    }
    if (!delegatePublicKey?.startsWith("ed25519:")) {
        throw new Error("delegatePublicKey must be in 'ed25519:<base64>' format");
    }
    if (!constraints || typeof constraints !== "object") {
        throw new Error("constraints must be an object");
    }

    const now = issuedAt ? new Date(issuedAt) : new Date();
    const expires = new Date(now.getTime() + ttlSeconds * 1000);

    const cdt: Record<string, unknown> = {
        version: "1.0",
        token_id: tokenId || `urn:uuid:${globalThis.crypto.randomUUID()}`,
        issued_at: now.toISOString().replace(/\.\d{3}Z$/, "Z"),
        expires_at: expires.toISOString().replace(/\.\d{3}Z$/, "Z"),
        delegator: delegatorUri,
        delegate: delegateUri,
        delegate_public_key: delegatePublicKey,
        constraints,
    };

    if (intentHash) {
        cdt.intent_hash = intentHash;
    }

    const canonical = canonicalize(cdt);
    const privateKey = createPrivateKey(delegatorPrivateKeyPem);
    const sigBytes = sign(null, Buffer.from(canonical, "utf-8"), privateKey);
    cdt.signature = sigBytes.toString("base64");

    return cdt;
}

/**
 * Computes a Proof-of-Possession (PoP) signature header per CREDUENT-007 Section 3.3.
 */
export function signPopHeader(params: {
    delegatePrivateKeyPem: string;
    httpMethod: string;
    uriPath: string;
    tokenId: string;
    timestamp?: string;
}): { popSignature: string; timestamp: string } {
    const { delegatePrivateKeyPem, httpMethod, uriPath, tokenId } = params;
    const timestamp = params.timestamp || new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

    const message = `${httpMethod.toUpperCase()}|${uriPath}|${timestamp}|${tokenId}`;
    const privateKey = createPrivateKey(delegatePrivateKeyPem);
    const sigBytes = sign(null, Buffer.from(message, "utf-8"), privateKey);

    return {
        popSignature: sigBytes.toString("base64"),
        timestamp,
    };
}

/**
 * Verifies a Proof-of-Possession (PoP) signature header per CREDUENT-007 Section 3.3.
 */
export async function verifyPopHeader(params: {
    popSignature: string;
    timestamp: string;
    delegatePublicKey: string;
    httpMethod: string;
    uriPath: string;
    tokenId: string;
    maxSkewSeconds?: number;
}): Promise<boolean> {
    const { popSignature, timestamp, delegatePublicKey, httpMethod, uriPath, tokenId, maxSkewSeconds = 60 } = params;

    if (!popSignature || !timestamp || !delegatePublicKey) {
        return false;
    }

    try {
        const ts = new Date(timestamp).getTime();
        const now = Date.now();
        const skew = Math.abs((now - ts) / 1000);
        if (skew > maxSkewSeconds) {
            return false;
        }

        const message = `${httpMethod.toUpperCase()}|${uriPath}|${timestamp}|${tokenId}`;
        const prefix = "ed25519:";
        if (!delegatePublicKey.startsWith(prefix)) return false;

        const rawKey = Uint8Array.from(atob(delegatePublicKey.slice(prefix.length)), (c) => c.charCodeAt(0));
        const cryptoKey = await globalThis.crypto.subtle.importKey("raw", rawKey, { name: "Ed25519" }, false, [
            "verify",
        ]);

        const sigBytes = Uint8Array.from(atob(popSignature), (c) => c.charCodeAt(0));
        const dataBytes = new TextEncoder().encode(message);

        return await globalThis.crypto.subtle.verify({ name: "Ed25519" }, cryptoKey, sigBytes, dataBytes);
    } catch {
        return false;
    }
}

/**
 * Verifies a recursive chain of Creduent Delegation Tokens (CDTs).
 */
export async function verifyDelegationChain(params: {
    cdtChain: Array<Record<string, unknown>>;
    targetAction?: string;
    requiredCapability?: string;
    popSignature?: string;
    popTimestamp?: string;
    httpMethod?: string;
    uriPath?: string;
    trustedPublicKeys?: Record<string, string>;
    maxChainDepth?: number;
    maxClockSkewSeconds?: number;
}): Promise<DelegationVerifyResult> {
    const {
        cdtChain,
        targetAction,
        requiredCapability,
        popSignature,
        popTimestamp,
        httpMethod,
        uriPath,
        trustedPublicKeys = {},
        maxChainDepth = 8,
        maxClockSkewSeconds = 300,
    } = params;

    if (!Array.isArray(cdtChain) || cdtChain.length === 0) {
        return {
            valid: false,
            error: "Delegation chain is empty or malformed",
            errorCode: "CDT_MALFORMED",
            chainDepth: 0,
        };
    }

    if (cdtChain.length > maxChainDepth) {
        return {
            valid: false,
            error: `Delegation chain length (${cdtChain.length}) exceeds maximum allowed depth (${maxChainDepth})`,
            errorCode: "CDT_CHAIN_DEPTH_EXCEEDED",
            chainDepth: cdtChain.length,
        };
    }

    const now = Date.now();
    let prevToken: Record<string, unknown> | null = null;

    for (let i = 0; i < cdtChain.length; i++) {
        const cdt = cdtChain[i];

        const requiredFields = [
            "version",
            "token_id",
            "issued_at",
            "expires_at",
            "delegator",
            "delegate",
            "delegate_public_key",
            "constraints",
            "signature",
        ];

        for (const field of requiredFields) {
            if (!(field in cdt)) {
                return {
                    valid: false,
                    error: `CDT token at index ${i} missing required field: ${field}`,
                    errorCode: "CDT_MALFORMED",
                    chainDepth: i + 1,
                };
            }
        }

        const issuedAtMs = new Date(cdt.issued_at as string).getTime();
        const expiresAtMs = new Date(cdt.expires_at as string).getTime();

        if (isNaN(issuedAtMs) || isNaN(expiresAtMs)) {
            return {
                valid: false,
                error: `Invalid timestamp in CDT at index ${i}`,
                errorCode: "CDT_MALFORMED",
                chainDepth: i + 1,
            };
        }

        if ((issuedAtMs - now) / 1000 > maxClockSkewSeconds) {
            return {
                valid: false,
                error: `CDT token at index ${i} is not yet valid (issued_at in future)`,
                errorCode: "CDT_NOT_YET_VALID",
                chainDepth: i + 1,
            };
        }

        if (expiresAtMs <= now) {
            return {
                valid: false,
                error: `CDT token at index ${i} has expired`,
                errorCode: "CDT_EXPIRED",
                chainDepth: i + 1,
            };
        }

        // Cryptographic check
        const delegatorUri = cdt.delegator as string;
        let delegatorPubkey: string | undefined;

        if (i > 0 && prevToken) {
            if (delegatorUri !== prevToken.delegate) {
                return {
                    valid: false,
                    error: `Chain continuity broken at hop ${i}: delegator ${delegatorUri} != parent delegate ${prevToken.delegate}`,
                    errorCode: "CDT_KEY_MISMATCH",
                    chainDepth: i + 1,
                };
            }
            delegatorPubkey = prevToken.delegate_public_key as string;
        } else {
            delegatorPubkey = trustedPublicKeys[delegatorUri];
        }

        if (delegatorPubkey) {
            const payloadCopy = { ...cdt };
            delete payloadCopy.signature;
            const canonical = canonicalize(payloadCopy);
            const verified = await verifySignature(delegatorPubkey, cdt.signature as string, canonical);
            if (!verified) {
                return {
                    valid: false,
                    error: `Ed25519 signature invalid for delegator ${delegatorUri} at hop ${i}`,
                    errorCode: "CDT_SIGNATURE_INVALID",
                    chainDepth: i + 1,
                };
            }
        }

        // Constraint Narrowing
        const constraints = (cdt.constraints as Record<string, unknown>) || {};
        const allowedCaps = constraints.allowed_capabilities as string[] | undefined;

        if (prevToken) {
            const prevConstraints = (prevToken.constraints as Record<string, unknown>) || {};
            const prevCaps = prevConstraints.allowed_capabilities as string[] | undefined;

            if (allowedCaps && prevCaps) {
                const prevSet = new Set(prevCaps);
                const isSubset = allowedCaps.every((c) => prevSet.has(c));
                if (!isSubset) {
                    return {
                        valid: false,
                        error: `Privilege escalation at hop ${i}: capabilities exceed parent`,
                        errorCode: "CDT_PRIVILEGE_ESCALATION",
                        chainDepth: i + 1,
                    };
                }
            }

            const childRev = constraints.max_reversibility as string | undefined;
            const parentRev = prevConstraints.max_reversibility as string | undefined;
            if (childRev && parentRev) {
                const cRank = REVERSIBILITY_ORDER[childRev] ?? 99;
                const pRank = REVERSIBILITY_ORDER[parentRev] ?? 99;
                if (cRank > pRank) {
                    return {
                        valid: false,
                        error: `Privilege escalation at hop ${i}: reversibility '${childRev}' exceeds parent '${parentRev}'`,
                        errorCode: "CDT_PRIVILEGE_ESCALATION",
                        chainDepth: i + 1,
                    };
                }
            }
        }

        prevToken = cdt;
    }

    const leafToken = cdtChain[cdtChain.length - 1];
    const leafConstraints = (leafToken.constraints as Record<string, unknown>) || {};
    const leafCaps = (leafConstraints.allowed_capabilities as string[]) || [];
    const leafTools = (leafConstraints.allowed_tools as string[]) || [];

    if (requiredCapability && !leafCaps.includes(requiredCapability)) {
        return {
            valid: false,
            error: `Required capability '${requiredCapability}' not in leaf token capabilities`,
            errorCode: "CDT_CONSTRAINT_VIOLATION",
            chainDepth: cdtChain.length,
        };
    }

    if (targetAction && leafTools.length > 0 && !leafTools.includes(targetAction)) {
        return {
            valid: false,
            error: `Target tool '${targetAction}' not in leaf token allowed_tools`,
            errorCode: "CDT_CONSTRAINT_VIOLATION",
            chainDepth: cdtChain.length,
        };
    }

    if (popSignature || popTimestamp || httpMethod || uriPath) {
        if (!popSignature || !popTimestamp) {
            return {
                valid: false,
                error: "Proof-of-Possession signature and timestamp required",
                errorCode: "CDT_POP_SIGNATURE_REQUIRED",
                chainDepth: cdtChain.length,
            };
        }

        const popValid = await verifyPopHeader({
            popSignature,
            timestamp: popTimestamp,
            delegatePublicKey: leafToken.delegate_public_key as string,
            httpMethod: httpMethod || "POST",
            uriPath: uriPath || "/",
            tokenId: leafToken.token_id as string,
        });

        if (!popValid) {
            return {
                valid: false,
                error: "Proof-of-Possession signature verification failed or timestamp expired",
                errorCode: "CDT_POP_SIGNATURE_INVALID",
                chainDepth: cdtChain.length,
            };
        }
    }

    return {
        valid: true,
        chainDepth: cdtChain.length,
        rootDelegator: cdtChain[0].delegator as string,
        leafDelegate: leafToken.delegate as string,
        allowedCapabilities: leafCaps,
        allowedTools: leafTools,
        maxReversibility: leafConstraints.max_reversibility as string | undefined,
    };
}

