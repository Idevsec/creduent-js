import { verify } from "../verify.js";
import { VerifyResult } from "../types.js";

/**
 * A LangGraph node function that verifies a Creduent agent URI.
 * It expects the state to contain an `agentUri` key.
 * It returns an updated state with `verificationResult`.
 *
 * @param state - Graph state containing agentUri
 * @param options - Configuration options (e.g. strict mode)
 */
export async function verifyAgentNode<T extends { agentUri?: string }>(
  state: T,
  options?: { strict?: boolean }
): Promise<{
  verificationResult: {
    verified: boolean;
    agent_id?: string;
    public_key?: string;
    endpoint?: string;
    capabilities?: string[];
    error?: string;
  };
}> {
  const agentUri = state.agentUri;
  if (!agentUri) {
    if (options?.strict) {
      throw new Error("No agentUri found in graph state.");
    }
    return {
      verificationResult: {
        verified: false,
        error: "No agentUri provided in state.",
      },
    };
  }

  try {
    const result = await verify(agentUri);
    const verificationResult = {
      verified: result.valid,
      agent_id: result.agent_id,
      public_key: result.document?.public_key || "",
      endpoint: result.document?.endpoint || "",
      capabilities: result.document?.capabilities || [],
      error: result.reason || undefined,
    };

    if (!result.valid && options?.strict) {
      throw new Error(`Creduent verification failed for ${agentUri}: ${result.reason}`);
    }

    return { verificationResult };
  } catch (error: any) {
    if (options?.strict) {
      throw error;
    }
    return {
      verificationResult: {
        verified: false,
        error: error.message || String(error),
      },
    };
  }
}
