/*
 * Copyright 2026 IDevSec
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export interface DidOptions {
  method?: "creduent" | "web";
  domain?: string;
}

/**
 * Converts a Creduent agent:// URI into a W3C DID URI (did:creduent or did:web).
 */
export function agentToDid(agentId: string, options?: DidOptions): string {
  if (!agentId.startsWith("agent://")) {
    throw new Error(`Invalid agent_id scheme: ${agentId}. Expected 'agent://...'`);
  }

  const rawPath = agentId.slice(8).replace(/^\/+|\/+$/g, "");
  const parts = rawPath.split("/");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error(`Invalid agent_id format: ${agentId}. Expected 'agent://namespace/name'`);
  }

  const [namespace, name] = parts;
  const method = options?.method || "creduent";

  if (method === "creduent") {
    return `did:creduent:${namespace}:${name}`;
  } else if (method === "web") {
    const targetDomain = options?.domain || `${namespace}.com`;
    const cleanDomain = targetDomain.replace(/\//g, ":");
    return `did:web:${cleanDomain}:agent:${name}`;
  } else {
    throw new Error(`Unsupported DID method: '${method}'. Supported methods: 'creduent', 'web'`);
  }
}

/**
 * Parses a did:creduent or did:web URI back into a Creduent agent:// URI.
 */
export function didToAgent(didUri: string): string {
  if (didUri.startsWith("did:creduent:")) {
    const parts = didUri.slice(13).split(":");
    if (parts.length >= 2) {
      const [namespace, name] = parts;
      return `agent://${namespace}/${name}`;
    }
    throw new Error(`Invalid did:creduent format: ${didUri}`);
  } else if (didUri.startsWith("did:web:")) {
    const parts = didUri.slice(8).split(":");
    if (parts.length >= 3 && parts[parts.length - 2] === "agent") {
      const name = parts[parts.length - 1];
      const domain = parts[0];
      const namespace = domain.split(".")[0];
      return `agent://${namespace}/${name}`;
    } else if (parts.length >= 2) {
      const namespace = parts[0].split(".")[0];
      const name = parts[parts.length - 1];
      return `agent://${namespace}/${name}`;
    }
    throw new Error(`Invalid did:web format: ${didUri}`);
  }

  throw new Error(`Unsupported DID scheme: ${didUri}. Expected 'did:creduent:' or 'did:web:'`);
}

/**
 * Generates a standard W3C DID Document (JSON-LD) from a Creduent agent.json dictionary or record.
 */
export function agentToDidDocument(
  agentData: Record<string, any>,
  options?: DidOptions
): Record<string, any> {
  const agentId = agentData.agent_id || agentData.identity?.agent_id;
  if (!agentId) {
    throw new Error("agentData missing required 'agent_id' field");
  }

  const didId = agentToDid(agentId, options);
  let publicKey = agentData.public_key;
  if (!publicKey && agentData.identity?.keys && agentData.identity.keys.length > 0) {
    publicKey = agentData.identity.keys[0].public_key;
  }

  const keyId = `${didId}#key-1`;
  const endpoint = agentData.endpoint || agentData.identity?.endpoint || "";

  const didDoc: Record<string, any> = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    id: didId,
    alsoKnownAs: [agentId],
    verificationMethod: [
      {
        id: keyId,
        type: "Ed25519VerificationKey2020",
        controller: didId,
        publicKeyMultibase: publicKey || ""
      }
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    service: []
  };

  if (endpoint) {
    didDoc.service.push({
      id: `${didId}#endpoint`,
      type: "AgentServiceEndpoint",
      serviceEndpoint: endpoint
    });
  }

  return didDoc;
}
