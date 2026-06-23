import { createPrivateKey, sign } from "crypto";
import { canonicalize } from "./crypto.js";

/**
 * Signs a payload object using JSON Canonicalization Scheme (JCS) and Ed25519.
 * 
 * @param payloadObj The JSON payload to sign
 * @param privateKeyPem The private key in PEM format
 * @returns Base64-encoded signature string
 */
export function signPayload(payloadObj: object, privateKeyPem: string): string {
  const canonicalStr = canonicalize(payloadObj);
  const canonicalBytes = Buffer.from(canonicalStr, "utf-8");
  const privateKeyObj = createPrivateKey(privateKeyPem);
  const signatureBytes = sign(null, canonicalBytes, privateKeyObj);
  return signatureBytes.toString("base64");
}
