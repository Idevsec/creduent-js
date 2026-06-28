import {
  AgentRecord,
  RegisterPayload,
  ClientOptions,
  RenewPayload,
  RenewResult,
  WebhookPayload,
  WebhookResult,
  DiscoveryResult
} from "./types.js";
import { verify } from "./verify.js";
import { signPayload } from "./sign.js";

const DEFAULT_BASE_URL = "https://creduent.idevsec.com";

export class CreduentError extends Error {
  constructor(message: string, public statusCode?: number, public responseText?: string) {
    super(message);
    this.name = "CreduentError";
  }
}

export class AgentNotFoundError extends CreduentError {
  constructor(uri: string) {
    super(`Agent '${uri}' is not registered or has no active cryptographic attestation record.`, 404);
    this.name = "AgentNotFoundError";
  }
}

/**
 * Normalizes an agent URI to ensure it follows the canonical 'agent://<domain>/<path>' format.
 */
function normalizeAgentUri(uri: string): string {
  let cleaned = uri.trim();
  if (cleaned.startsWith("agent:/") && !cleaned.startsWith("agent://")) {
    cleaned = "agent://" + cleaned.substring(7);
  } else if (cleaned.startsWith("agent:") && !cleaned.startsWith("agent://") && !cleaned.startsWith("agent:/")) {
    cleaned = "agent://" + cleaned.substring(6);
  } else if (!cleaned.startsWith("agent://")) {
    cleaned = "agent://" + cleaned;
  }
  return cleaned;
}

/**
 * Helper to build headers and fetch JSON from the registry securely.
 */
async function request<T>(
  url: string,
  method: "GET" | "POST",
  body?: any,
  options?: ClientOptions
): Promise<T> {
  const headers = {
    "Content-Type": "application/json",
    ...options?.headers,
  };

  const fetchOptions: RequestInit = {
    method,
    headers,
  };

  if (body) {
    fetchOptions.body = JSON.stringify(body);
  }

  let response: Response;
  try {
    response = await fetch(url, fetchOptions);
  } catch (error: any) {
    throw new CreduentError(`Failed to connect to the Creduent Registry: ${error.message}`);
  }

  if (response.status === 404) {
    throw new AgentNotFoundError(url.substring(url.indexOf("agent:")));
  }

  const text = await response.text();
  if (!response.ok) {
    throw new CreduentError(
      `Creduent Registry returned an unexpected error (${response.status} ${response.statusText}): ${text}`,
      response.status,
      text
    );
  }

  try {
    return JSON.parse(text) as T;
  } catch (err) {
    throw new CreduentError(`Registry response is not valid JSON: ${text}`, response.status, text);
  }
}

/**
 * Resolves an AI agent's attestation record by their agent:// URI.
 * 
 * @param uri The agent:// URI of the AI agent
 * @param options Configurable options including custom registry baseUrl
 * @returns Full agent attestation record
 */
export async function resolveAgent(uri: string, options?: ClientOptions): Promise<AgentRecord> {
  const baseUrl = options?.baseUrl?.replace(/\/$/, "") || DEFAULT_BASE_URL;
  const normalizedUri = normalizeAgentUri(uri);
  
  // Construct the URL: e.g. https://creduent.idevsec.com/agent://creduent/reconbot
  const url = `${baseUrl}/${normalizedUri}`;
  return request<AgentRecord>(url, "GET", undefined, options);
}

/**
 * Verifies an AI agent identity and confirms their attestation state.
 * 
 * @param uri The agent:// URI of the AI agent
 * @param options Configurable options including custom registry baseUrl
 * @returns True if the agent is registered and has a level of "verified", false otherwise
 */
export async function verifyAgent(uri: string, options?: ClientOptions): Promise<boolean> {
  try {
    const record = await resolveAgent(uri, options);
    return record.level === "verified" || record.level === "trusted";
  } catch (error) {
    if (error instanceof AgentNotFoundError) {
      return false;
    }
    if (error instanceof CreduentError && error.statusCode === 410) {
      return false;
    }
    throw error;
  }
}


/**
 * Registers an AI agent with the Creduent Attestation Registry.
 * 
 * @param payload Registration payload details
 * @param options Configurable options including custom registry baseUrl
 * @returns The created attestation record
 */
export async function registerAgent(payload: RegisterPayload, options?: ClientOptions): Promise<AgentRecord> {
  const baseUrl = options?.baseUrl?.replace(/\/$/, "") || DEFAULT_BASE_URL;
  
  // Normalise the agent ID inside payload
  const normalizedPayload = {
    ...payload,
    agent_id: normalizeAgentUri(payload.agent_id),
  };

  const url = `${baseUrl}/registry/register`;
  return request<AgentRecord>(url, "POST", normalizedPayload, options);
}

/**
 * Renews an agent's cryptographic attestation.
 */
export async function renewAgent(payload: RenewPayload, options?: ClientOptions): Promise<RenewResult> {
  const baseUrl = options?.baseUrl?.replace(/\/$/, "") || DEFAULT_BASE_URL;
  
  const normalizedPayload = {
    ...payload,
    agent_id: normalizeAgentUri(payload.agent_id),
  };

  const url = `${baseUrl}/registry/renew`;
  return request<RenewResult>(url, "POST", normalizedPayload, options);
}

/**
 * Registers a webhook URL for an agent.
 */
export async function registerWebhook(payload: WebhookPayload, options?: ClientOptions): Promise<WebhookResult> {
  const baseUrl = options?.baseUrl?.replace(/\/$/, "") || DEFAULT_BASE_URL;
  
  const normalizedPayload = {
    ...payload,
    agent_id: normalizeAgentUri(payload.agent_id),
  };

  const url = `${baseUrl}/registry/webhook/register`;
  return request<WebhookResult>(url, "POST", normalizedPayload, options);
}

/**
 * Queries the webhook URL registered for an agent.
 */
export async function queryWebhook(agentId: string, options?: ClientOptions): Promise<WebhookResult> {
  const baseUrl = options?.baseUrl?.replace(/\/$/, "") || DEFAULT_BASE_URL;
  const normalizedAgentId = normalizeAgentUri(agentId);

  const url = `${baseUrl}/registry/webhook/${encodeURIComponent(normalizedAgentId)}`;
  return request<WebhookResult>(url, "GET", undefined, options);
}

/**
 * Discovers an agent's capabilities.
 * If myAgentId and privateKeyPem are provided, it signs a short-lived discovery token
 * and requests private capabilities from the target agent's /discover endpoint.
 */
export async function discoverAgent(
  targetUri: string,
  myAgentId?: string,
  privateKeyPem?: string,
  options?: ClientOptions
): Promise<DiscoveryResult> {
  const targetNormalized = normalizeAgentUri(targetUri);
  let verifyResult;
  try {
    verifyResult = await verify(targetNormalized);
    if (!verifyResult.valid || !verifyResult.document) {
      return {
        target_agent_id: targetNormalized,
        authenticated: false,
        error: `Target agent verification failed: ${verifyResult.reason || "unknown reason"}`,
      };
    }
  } catch (error: any) {
    return {
      target_agent_id: targetNormalized,
      authenticated: false,
      error: `Failed to fetch target agent identity: ${error.message}`,
    };
  }

  const doc = verifyResult.document;
  const endpoint = doc.endpoint;
  const publicCaps = doc.capabilities || [];

  if (!endpoint || !myAgentId || !privateKeyPem) {
    return {
      target_agent_id: doc.agent_id || targetNormalized,
      endpoint,
      capabilities: publicCaps,
      authenticated: false,
    };
  }

  const payload = {
    iss: normalizeAgentUri(myAgentId),
    aud: doc.agent_id,
    exp: Math.floor(Date.now() / 1000) + 60,
    action: "discover",
  };

  let signature;
  try {
    signature = signPayload(payload, privateKeyPem);
  } catch (error: any) {
    return {
      target_agent_id: doc.agent_id || targetNormalized,
      endpoint,
      capabilities: publicCaps,
      authenticated: false,
      error: `Failed to sign discovery request: ${error.message}`,
    };
  }

  const discoverUrl = endpoint.replace(/\/$/, "") + "/discover";
  try {
    const res = await fetch(discoverUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        ...payload,
        signature,
      }),
    });

    if (res.status === 200) {
      const data = await res.json();
      const privateCaps = data.capabilities || [];
      const merged = [...publicCaps];
      for (const cap of privateCaps) {
        if (!merged.includes(cap)) {
          merged.push(cap);
        }
      }
      return {
        target_agent_id: doc.agent_id || targetNormalized,
        endpoint,
        capabilities: merged,
        authenticated: true,
      };
    } else {
      const errText = await res.text();
      return {
        target_agent_id: doc.agent_id || targetNormalized,
        endpoint,
        capabilities: publicCaps,
        authenticated: false,
        error: `Authenticated discovery failed with HTTP ${res.status}: ${errText}`,
      };
    }
  } catch (error: any) {
    return {
      target_agent_id: doc.agent_id || targetNormalized,
      endpoint,
      capabilities: publicCaps,
      authenticated: false,
      error: `Network error during authenticated discovery: ${error.message}`,
    };
  }
}


