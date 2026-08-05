import createCrypto from "crypto";
import {
  ReversibilityClass,
  REVERSIBILITY_PRECEDENCE,
  normalizeReversibilityClass,
} from "./provenance.js";

export class LedgerIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LedgerIntegrityError";
  }
}

export interface Receipt {
  step_index?: number;
  agent_id?: string;
  tool_name?: string;
  reversibility_class?: string;
  previous_receipt_hash?: string;
  chain_id?: string;
  provenance_source?: string;
  is_registry_bound?: boolean;
  [key: string]: any;
}

export interface LedgerChainMetadata {
  chain_id: string;
  total_steps: number;
  latest_hash: string;
  status?: string;
}

export class LedgerClient {
  private baseUrl: string;

  constructor(baseUrl: string = "https://creduent.idevsec.com") {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
  }

  public async getChainMetadata(chainId: string): Promise<LedgerChainMetadata> {
    const url = `${this.baseUrl}/ledger/chain/${chainId}`;
    try {
      const response = await fetch(url);
      if (response.ok) {
        return (await response.json()) as LedgerChainMetadata;
      }
      throw new LedgerIntegrityError(
        `Failed to query ledger for chain '${chainId}': HTTP status ${response.status}`
      );
    } catch (e: any) {
      if (e instanceof LedgerIntegrityError) {
        throw e;
      }
      throw new LedgerIntegrityError(
        `Ledger connectivity failure for chain '${chainId}': ${e.message || String(e)}`
      );
    }
  }
}

export class LedgerChainVerifier {
  public static verifyLedgerChain(receipts: Receipt[]): boolean {
    if (!receipts || receipts.length === 0) {
      throw new LedgerIntegrityError("Receipt chain is empty.");
    }

    let prevHash = "GENESIS";

    for (let idx = 0; idx < receipts.length; idx++) {
      const receipt = receipts[idx];
      const stepIndex = receipt.step_index ?? idx;

      if (stepIndex !== idx) {
        throw new LedgerIntegrityError(
          `Chain step index mismatch at pos ${idx}: expected ${idx}, got ${stepIndex}`
        );
      }

      const recordedPrevHash = receipt.previous_receipt_hash || "GENESIS";
      if (recordedPrevHash !== prevHash) {
        throw new LedgerIntegrityError(
          `Chain hash mismatch at step ${idx}: recorded prev ${recordedPrevHash}, expected ${prevHash}`
        );
      }

      const receiptCore = {
        agent_id: receipt.agent_id,
        previous_receipt_hash: recordedPrevHash,
        reversibility_class: receipt.reversibility_class,
        step_index: stepIndex,
        tool_name: receipt.tool_name,
      };

      const canonicalStr = JSON.stringify(receiptCore, Object.keys(receiptCore).sort());
      const hash = createCrypto.createHash("sha256").update(canonicalStr, "utf-8").digest("hex");
      prevHash = hash;
    }

    return true;
  }

  public static async reduceWorstCaseReversibility(
    receipts: Receipt[],
    chainId?: string,
    ledgerClient?: LedgerClient
  ): Promise<[string, number]> {
    if (!receipts || receipts.length === 0) {
      throw new LedgerIntegrityError("Receipt chain is empty.");
    }

    // 1. Verify hash chain continuity from GENESIS
    this.verifyLedgerChain(receipts);

    // 2. Independent Ledger Count Check
    const targetChainId = chainId || receipts[0].chain_id;
    if (targetChainId && ledgerClient) {
      const ledgerMeta = await ledgerClient.getChainMetadata(targetChainId);
      const expectedTotal = ledgerMeta.total_steps;
      if (expectedTotal !== undefined && receipts.length !== expectedTotal) {
        throw new LedgerIntegrityError(
          `Chain Truncation Attack Detected: Independent ledger records ${expectedTotal} steps for chain '${targetChainId}', but payload only contains ${receipts.length} steps.`
        );
      }
    }

    const validatedCount = receipts.length;
    let worstCase: string = ReversibilityClass.READ_ONLY;
    let highestRank = 0;

    for (const receipt of receipts) {
      const rawClass = normalizeReversibilityClass(
        {
          name: receipt.tool_name,
          reversibility_class: receipt.reversibility_class,
        },
        receipt.provenance_source,
        receipt.is_registry_bound || false
      );

      let rank = 0;
      for (let idx = 0; idx < REVERSIBILITY_PRECEDENCE.length; idx++) {
        if (REVERSIBILITY_PRECEDENCE[idx] === rawClass) {
          rank = idx;
          break;
        }
      }

      if (rank > highestRank) {
        highestRank = rank;
        worstCase = rawClass;
      }
    }

    return [worstCase, validatedCount];
  }
}
