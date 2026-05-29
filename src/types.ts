export interface AgentRecord {
  agent_id: string;
  issuer: string;
  level: "verified" | "unverified" | "revoked";
  domain: string;
  public_key: string;
  registered_at: string;
}

export interface RegisterPayload {
  agent_id: string;
  domain: string;
  public_key: string;
  metadata?: Record<string, string>;
}

export interface ClientOptions {
  baseUrl?: string;
  headers?: Record<string, string>;
}
