import { AgentDocument, VerifyResult, KeyRecord } from "./types.js";
import { canonicalize, verifySignature } from "./crypto.js";

const DEFAULT_REGISTRY_URL = "https://registry.idevsec.com";

/**
 * Resolves an agent:// URI, http(s) URL, or domain to a well-known agent.json
 */
export async function resolveTarget(target: string): Promise<AgentDocument> {
  let url = target;

  if (target.startsWith("agent://")) {
    // @ts-ignore
    const envUrl = typeof process !== "undefined" && process.env ? process.env.CREDUENT_REGISTRY_URL : undefined;
    const registryUrl = envUrl || DEFAULT_REGISTRY_URL;
    url = `${registryUrl}/attest/${encodeURIComponent(target)}`;
  } else if (!target.startsWith("http")) {
    url = `https://${target}/.well-known/agent.json`;
  }

  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch agent.json: ${res.statusText}`);
  }

  return (await res.json()) as AgentDocument;
}

/**
 * Cryptographically verifies an agent identity document using Ed25519 and JCS.
 * Performs fully local verification — no registry trust required for signature check.
 *
 * @param target - An agent:// URI, domain, HTTPS URL, or a pre-fetched AgentDocument
 */
export async function verify(target: string | AgentDocument): Promise<VerifyResult> {
  let doc: AgentDocument;

  try {
    if (typeof target === "string") {
      doc = await resolveTarget(target);
    } else {
      doc = target;
    }
  } catch (error: any) {
    return { valid: false, reason: error.message || "Resolution failed" };
  }

  if (doc.version === "2.0") {
    if (!doc.identity || !doc.policy) {
      return { valid: false, reason: "v2.0 agent document must contain identity and policy objects", document: doc };
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

  for (const key of keys) {
    const isValid = await verifySignature(key, signature, canonicalData);
    if (isValid) {
      return { valid: true, agent_id: doc.version === "2.0" ? doc.identity?.agent_id : doc.agent_id, document: doc };
    }
  }

  return { valid: false, reason: "Signature verification failed", document: doc };
}
