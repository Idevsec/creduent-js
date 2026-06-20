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

export interface KeyRecord {
  public_key: string;
  status: "active" | "revoked";
  expires_at?: string;
  revoked_at?: string;
}

export interface AgentDocument {
  version: string;
  agent_id: string;
  owner?: string;
  public_key?: string;
  keys?: KeyRecord[];
  endpoint?: string;
  capabilities?: string[];
  issued_at?: string;
  signature?: string;
  [key: string]: any;
}

export interface VerifyResult {
  valid: boolean;
  agent_id?: string;
  reason?: string;
  document?: AgentDocument;
}
