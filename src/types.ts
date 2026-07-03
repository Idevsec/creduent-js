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

export interface RenewPayload {
    agent_id: string;
    new_expires_at: string;
    signature: string;
}

export interface RenewResult extends AgentRecord {}

export interface WebhookPayload {
    agent_id: string;
    webhook_url: string;
    signature: string;
}

export interface WebhookResult {
    agent_id: string;
    webhook_url: string;
}

export interface DiscoveryResult {
    target_agent_id: string;
    endpoint?: string;
    capabilities?: string[];
    authenticated: boolean;
    error?: string;
}
