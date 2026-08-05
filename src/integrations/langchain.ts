import { verify } from "../verify.js";
import { normalizeReversibilityClass, ToolMetadata } from "../provenance.js";

export interface CreduentVerifyOptions {
    strict?: boolean;
    toolMetadata?: ToolMetadata;
    provenanceSource?: string;
    isRegistryBound?: boolean;
}

/**
 * Creates a verification handler compatible with LangChain JS/TS tool execution.
 * Normalizes tool reversibility class at entry boundary, then verifies the target agent URI.
 *
 * @param agentUri - The target Creduent agent URI (agent://namespace/name)
 * @param options - Execution options (strict mode throws error on failed verification)
 */
export async function verifyCreduentAgent(
    agentUri: string,
    options: CreduentVerifyOptions = { strict: true }
): Promise<{
    verified: boolean;
    agent_id?: string;
    capabilities?: string[];
    reversibility_class?: string;
    error?: string;
}> {
    const reversibilityClass = normalizeReversibilityClass(
        options.toolMetadata,
        options.provenanceSource,
        options.isRegistryBound
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
            const errorMsg = `Creduent verification failed for ${agentUri}: ${result.reason || "Invalid signature"}`;
            if (options.strict) {
                throw new Error(errorMsg);
            }
            return { verified: false, error: errorMsg, reversibility_class: reversibilityClass };
        }
    } catch (error: any) {
        const errorMsg = error.message || String(error);
        if (options.strict) {
            throw error;
        }
        return { verified: false, error: errorMsg };
    }
}
