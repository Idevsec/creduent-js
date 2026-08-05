import { verify } from "../verify.js";
import { normalizeReversibilityClass, ToolMetadata } from "../provenance.js";

export interface CreduentLlamaIndexVerifyResult {
    verified: boolean;
    agent_id?: string;
    capabilities?: string[];
    reversibility_class?: string;
    error?: string;
}

/**
 * Creates a verification function for LlamaIndex TS FunctionTool and QueryEngine pipelines.
 * Normalizes tool reversibility class at the entry boundary via ProvenanceGuard.
 *
 * @param agentUri - The Creduent URI of the agent to verify
 * @param toolMetadata - Optional tool metadata for reversibility normalization
 * @param provenanceSource - Trusted registry/policy source
 * @param isRegistryBound - True if bound by verified policy
 */
export async function verifyLlamaIndexAgent(
    agentUri: string,
    toolMetadata?: ToolMetadata,
    provenanceSource?: string,
    isRegistryBound: boolean = false
): Promise<CreduentLlamaIndexVerifyResult> {
    const reversibilityClass = normalizeReversibilityClass(
        toolMetadata,
        provenanceSource,
        isRegistryBound
    );
    try {
        const result = await verify(agentUri);
        if (result.valid) {
            return {
                verified: true,
                agent_id: result.agent_id,
                capabilities: result.document?.capabilities || [],
                reversibility_class: reversibilityClass,
            };
        } else {
            return {
                verified: false,
                reversibility_class: reversibilityClass,
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
