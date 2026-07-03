import { z } from "zod";
import { verify } from "../verify.js";

/**
 * The Creduent Agent Verification tool definition for Vercel AI SDK.
 * Users can wrap this using the `tool()` helper from the `ai` package.
 */
export const creduentVerifyToolDefinition = {
    description: "Verifies the cryptographic identity of an external AI agent using the Creduent protocol.",
    parameters: z.object({
        agentUri: z.string().describe("The Creduent URI of the agent to verify, e.g. agent://namespace/name"),
    }),
    execute: async ({ agentUri }: { agentUri: string }) => {
        try {
            const result = await verify(agentUri);
            if (result.valid) {
                return {
                    success: true,
                    message: `Verification SUCCESS for ${agentUri}. Agent capabilities and keys are cryptographically trusted.`,
                    agent_id: result.agent_id,
                    capabilities: result.document?.capabilities || [],
                };
            } else {
                return {
                    success: false,
                    message: `Verification FAILED for ${agentUri}: ${result.reason || "Unknown error"}`,
                };
            }
        } catch (error: any) {
            return {
                success: false,
                message: `Verification process failed: ${error.message || error}`,
            };
        }
    },
};
