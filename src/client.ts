import { AgentRecord, RegisterPayload, ClientOptions } from "./types.js";

const DEFAULT_BASE_URL = "https://api.idevsec.com";

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
  
  // Construct the URL: e.g. https://api.idevsec.com/agent://creduent/reconbot
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

