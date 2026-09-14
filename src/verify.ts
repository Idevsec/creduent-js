import { AgentDocument, VerifyResult, KeyRecord } from "./types.js";
import { canonicalize, verifySignature } from "./crypto.js";

const DEFAULT_REGISTRY_URL = "https://creduent.idevsec.com";

interface CacheEntry {
    doc: AgentDocument;
    expiry: number;
}

const VERIFICATION_CACHE_TTL_MS = 300_000; // 5 minutes
const verificationCache = new Map<string, CacheEntry>();

/**
 * Flushes all entries from the local verification LRU cache.
 */
export function clearVerificationCache(): void {
    verificationCache.clear();
}

/**
 * Evicts a specific agent's document from the local LRU cache.
 */
export function invalidateAgentCache(target: string): void {
    verificationCache.delete(target);
}

/**
 * Queries DNS-over-HTTPS (DoH) via Cloudflare to verify if DNSSEC AD flag is true for a domain.
 */
export async function verifyDnssec(domain: string): Promise<boolean> {
    if (!domain || domain.includes("localhost") || domain.includes("127.0.0.1")) {
        return false;
    }
    try {
        let host = domain;
        if (domain.includes("://")) {
            host = new URL(domain).hostname;
        } else {
            host = domain.split("/")[0].split(":")[0];
        }
        if (!host) return false;

        const dohUrl = `https://1.1.1.1/dns-query?name=${encodeURIComponent(host)}&type=A`;
        const res = await fetch(dohUrl, { headers: { Accept: "application/dns-json" } });
        if (res.ok) {
            const data = (await res.json()) as { AD?: boolean };
            return Boolean(data.AD);
        }
    } catch (e) {
        // Fallback
    }
    return false;
}

/**
 * Resolves an agent:// URI, http(s) URL, or domain to a well-known agent.json
 */
export async function resolveTarget(target: string, useCache: boolean = true): Promise<AgentDocument> {
    if (target.includes("../") || target.includes("..\\") || target.includes("/./") || target.includes("\\.\\")) {
        throw new Error("Path traversal or relative path sequence detected in target URI.");
    }

    if (useCache) {
        const cached = verificationCache.get(target);
        if (cached && Date.now() < cached.expiry) {
            return cached.doc;
        }
        if (cached) {
            verificationCache.delete(target);
        }
    }

    let url = target;

    if (target.startsWith("agent://")) {
        // @ts-ignore
        const envUrl = typeof process !== "undefined" && process.env ? process.env.CREDUENT_REGISTRY_URL : undefined;
        const registryUrl = envUrl || DEFAULT_REGISTRY_URL;
        const attestUrl = `${registryUrl}/attest/${encodeURIComponent(target)}`;

        try {
            const res = await fetch(attestUrl);
            if (res.ok) {
                const attestation = await res.json();
                const domain = attestation.domain;
                if (domain) {
                    const scheme = domain.includes("localhost") || domain.includes("127.0.0.1") ? "http" : "https";
                    url = `${scheme}://${domain}/.well-known/agent.json`;

                    const finalRes = await fetch(url);
                    if (finalRes.ok) {
                        const doc = (await finalRes.json()) as AgentDocument;
                        if (useCache) {
                            verificationCache.set(target, { doc, expiry: Date.now() + VERIFICATION_CACHE_TTL_MS });
                        }
                        return doc;
                    }
                }
            }
        } catch (e) {
            // Fallback
        }

        // Fallback to default namespace resolution
        const namespace = target.substring(8).split("/")[0];
        url = `https://api.${namespace}.ai/.well-known/agent.json`;
    } else if (!target.startsWith("http")) {
        url = `https://${target}/.well-known/agent.json`;
    }

    const res = await fetch(url);
    if (!res.ok) {
        throw new Error(`Failed to fetch agent.json: ${res.statusText}`);
    }

    const doc = (await res.json()) as AgentDocument;
    if (useCache) {
        const cc = res.headers ? res.headers.get("Cache-Control") || "" : "";
        if (!cc.includes("no-cache") && !cc.includes("no-store")) {
            let ttlMs = VERIFICATION_CACHE_TTL_MS;
            const match = cc.match(/max-age=(\d+)/i);
            if (match) {
                const parsedSec = parseInt(match[1], 10);
                if (!isNaN(parsedSec)) {
                    ttlMs = Math.max(60, Math.min(86400, parsedSec)) * 1000;
                }
            }
            verificationCache.set(target, { doc, expiry: Date.now() + ttlMs });
        }
    }
    return doc;
}

/**
 * Cryptographically verifies an agent identity document using Ed25519 and JCS.
 * Performs fully local verification — no registry trust required for signature check.
 *
 * @param target - An agent:// URI, domain, HTTPS URL, or a pre-fetched AgentDocument
 * @param useCache - Whether to check or update local 5-min LRU cache. Default is true.
 */
export async function verify(target: string | AgentDocument, useCache: boolean = true): Promise<VerifyResult> {
    let doc: AgentDocument;

    try {
        if (typeof target === "string") {
            doc = await resolveTarget(target, useCache);
        } else {
            doc = target;
        }
    } catch (error: any) {
        return { valid: false, reason: error.message || "Resolution failed" };
    }


    if (doc.version === "2.0") {
        if (!doc.identity || !doc.policy) {
            return {
                valid: false,
                reason: "v2.0 agent document must contain identity and policy objects",
                document: doc,
            };
        }
        const identity = doc.identity;
        const policy = doc.policy;
        if (!identity.agent_id || !identity.keys || !identity.endpoint || !policy.capabilities) {
            return { valid: false, reason: "Invalid schema (missing required v2.0 fields)", document: doc };
        }
    } else {
        if (!doc.version || !doc.agent_id || !doc.capabilities) {
            return { valid: false, reason: "Invalid schema", document: doc };
        }
    }

    const owner = doc.version === "2.0" ? doc.identity?.owner : doc.owner;
    if (!owner || typeof owner !== "string" || (!owner.startsWith("mailto:") && !owner.startsWith("https://"))) {
        return { valid: false, reason: `Invalid owner scheme: '${owner}'. Owner must start with 'mailto:' or 'https://'`, document: doc };
    }

    const signature = doc.signature;
    if (!signature) {
        return { valid: false, reason: "No signature present", document: doc };
    }

    // Collect all active public keys
    const keys: string[] = [];
    if (doc.version === "2.0") {
        const identityKeys = doc.identity?.keys;
        if (Array.isArray(identityKeys)) {
            for (const keyRec of identityKeys) {
                if (keyRec.status === "active") keys.push(keyRec.public_key);
            }
        }
    } else {
        if (doc.public_key) keys.push(doc.public_key);
        if (Array.isArray(doc.keys)) {
            for (const keyRec of doc.keys as KeyRecord[]) {
                if (keyRec.status === "active") keys.push(keyRec.public_key);
            }
        }
    }

    if (keys.length === 0) {
        return { valid: false, reason: "No active public keys found", document: doc };
    }

    // Remove signature and canonicalize the payload
    const payload = { ...doc };
    delete payload.signature;
    const canonicalData = canonicalize(payload);

    const targetDomain = (doc.version === "2.0" ? doc.identity?.endpoint : doc.endpoint) || (typeof target === "string" ? target : "");
    const dnssecVerified = await verifyDnssec(targetDomain);

    for (const key of keys) {
        const isValid = await verifySignature(key, signature, canonicalData);
        if (isValid) {
            return {
                valid: true,
                agent_id: doc.version === "2.0" ? doc.identity?.agent_id : doc.agent_id,
                dnssec_verified: dnssecVerified,
                document: doc,
            };
        }
    }

    return { valid: false, reason: "Signature verification failed", document: doc };
}
