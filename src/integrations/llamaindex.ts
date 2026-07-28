import { verify } from "../verify.js";

export interface CreduentLlamaIndexVerifyResult {
    verified: boolean;
    agent_id?: string;
    capabilities?: string[];
    error?: string;
}

/**
 * Creates a verification function for LlamaIndex TS FunctionTool and QueryEngine pipelines.
 *
 * @param agentUri - The Creduent URI of the agent to verify
 */
export async function verifyLlamaIndexAgent(
    agentUri: string
): Promise<CreduentLlamaIndexVerifyResult> {
    try {
        const result = await verify(agentUri);
        if (result.valid) {
            return {
                verified: true,
                agent_id: result.agent_id,
                capabilities: result.document?.capabilities || [],
            };
        } else {
            return {
                verified: false,
                error: `Verification failed for ${agentUri}: ${result.reason || "Signature mismatch"}`,
            };
        }
    } catch (error: any) {
        return {
            verified: false,
            error: error.message || String(error),
        };
    }
}
