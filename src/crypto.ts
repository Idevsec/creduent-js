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
export async function verifySignature(
  publicKeyStr: string,
  signatureB64: string,
  data: string
): Promise<boolean> {
  try {
    const prefix = "ed25519:";
    if (!publicKeyStr.startsWith(prefix)) return false;

    const rawKey = Uint8Array.from(
      atob(publicKeyStr.slice(prefix.length)),
      (c) => c.charCodeAt(0)
    );

    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "Ed25519" },
      false,
      ["verify"]
    );

    const sigBytes = Uint8Array.from(atob(signatureB64), (c) =>
      c.charCodeAt(0)
    );
    const dataBytes = new TextEncoder().encode(data);

    return await globalThis.crypto.subtle.verify(
      { name: "Ed25519" },
      cryptoKey,
      sigBytes,
      dataBytes
    );
  } catch {
    return false;
  }
}
