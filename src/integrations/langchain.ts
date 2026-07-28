import { verify } from "../verify.js";

export interface CreduentVerifyOptions {
    strict?: boolean;
}

/**
 * Creates a verification handler compatible with LangChain JS/TS tool execution.
 * Verifies the target agent URI locally using WebCrypto and RFC 8785 JCS canonicalization.
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
    error?: string;
}> {
    try {
        const result = await verify(agentUri);
        if (result.valid) {
            return {
                verified: true,
                agent_id: result.agent_id,
                capabilities: result.document?.capabilities || [],
            };
        } else {
            const errorMsg = `Creduent verification failed for ${agentUri}: ${result.reason || "Invalid signature"}`;
            if (options.strict) {
                throw new Error(errorMsg);
            }
            return { verified: false, error: errorMsg };
        }
    } catch (error: any) {
        const errorMsg = error.message || String(error);
        if (options.strict) {
            throw error;
        }
        return { verified: false, error: errorMsg };
    }
}
