export interface AgentRecord {
  agent_id: string;
  issuer: string;
  level: "verified" | "trusted" | "unverified" | "revoked";
  domain: string;
  public_key: string;
  registered_at: string;
  issued_at: string;
  expires_at: string;
}

export interface RegisterPayload {
  agent_id: string;
  domain: string;
  agent_json_url: string;
  metadata?: Record<string, string>;
}


export interface ClientOptions {
  baseUrl?: string;
  headers?: Record<string, string>;
}
