/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) implementation.
 * Deterministic JSON serialization with lexicographically sorted keys.
 */
export function canonicalize(obj: unknown): string {
    if (obj === null) return "null";
    if (typeof obj !== "object") return JSON.stringify(obj);
    if (Array.isArray(obj)) {
        return "[" + obj.map((item) => canonicalize(item)).join(",") + "]";
    }
    const keys = Object.keys(obj as Record<string, unknown>).sort();
    const parts: string[] = [];
    for (const key of keys) {
        const value = (obj as Record<string, unknown>)[key];
        if (value !== undefined) {
            parts.push(JSON.stringify(key) + ":" + canonicalize(value));
        }
    }
    return "{" + parts.join(",") + "}";
}

/**
 * Verifies an Ed25519 signature using the Web Crypto API.
 * Compatible with Node.js 18+, Vercel Edge, Cloudflare Workers, and Deno.
 *
 * @param publicKeyStr - Public key in `ed25519:<base64>` format
 * @param signatureB64 - Base64-encoded signature
 * @param data - The canonicalized payload string
 */
export async function verifySignature(publicKeyStr: string, signatureB64: string, data: string): Promise<boolean> {
    try {
        const prefix = "ed25519:";
        if (!publicKeyStr.startsWith(prefix)) return false;

        const rawKey = Uint8Array.from(atob(publicKeyStr.slice(prefix.length)), (c) => c.charCodeAt(0));

        const cryptoKey = await globalThis.crypto.subtle.importKey("raw", rawKey, { name: "Ed25519" }, false, [
            "verify",
        ]);

        const sigBytes = Uint8Array.from(atob(signatureB64), (c) => c.charCodeAt(0));
        const dataBytes = new TextEncoder().encode(data);

        return await globalThis.crypto.subtle.verify({ name: "Ed25519" }, cryptoKey, sigBytes, dataBytes);
    } catch {
        return false;
    }
}

/**
 * Verifies an HMAC-SHA256 signature for a webhook payload.
 * Compatible with Node.js 18+, Vercel Edge, Cloudflare Workers, and Deno.
 *
 * @param secret - The webhook pre-shared secret key (starts with `whsec_`)
 * @param signatureHex - The hex-encoded signature from X-Creduent-Signature256 header
 * @param timestamp - The timestamp from X-Creduent-Timestamp header
 * @param payload - The webhook payload object (prior to JCS serialization)
 */
export async function verifyWebhookSignature(
    secret: string,
    signatureHex: string,
    timestamp: string,
    payload: unknown
): Promise<boolean> {
    try {
        const canonical = canonicalize(payload);
        const signedData = timestamp + "." + canonical;
        const encoder = new TextEncoder();
        const dataBytes = encoder.encode(signedData);
        const secretBytes = encoder.encode(secret);

        // Import HMAC key
        const key = await globalThis.crypto.subtle.importKey(
            "raw",
            secretBytes,
            { name: "HMAC", hash: { name: "SHA-256" } },
            false,
            ["verify"]
        );

        // Convert signature from hex string to bytes
        const signatureBytes = new Uint8Array(
            signatureHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
        );

        // Verify the signature
        return await globalThis.crypto.subtle.verify("HMAC", key, signatureBytes, dataBytes);
    } catch {
        return false;
    }
}

