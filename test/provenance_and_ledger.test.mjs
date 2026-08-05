import { test, describe } from "node:test";
import assert from "node:assert";
import {
  ProvenanceGuard,
  normalizeReversibilityClass,
  ReversibilityClass,
  LedgerChainVerifier,
  LedgerIntegrityError,
} from "../dist/esm/index.js";

describe("ProvenanceGuard unit tests", () => {
  test("missing metadata resolves to irreversible", () => {
    assert.strictEqual(normalizeReversibilityClass(null), ReversibilityClass.IRREVERSIBLE);
    assert.strictEqual(normalizeReversibilityClass(undefined), ReversibilityClass.IRREVERSIBLE);
    assert.strictEqual(normalizeReversibilityClass({}), ReversibilityClass.IRREVERSIBLE);
  });

  test("unclassified tool resolves to irreversible", () => {
    const meta = { name: "search_tool" };
    assert.strictEqual(normalizeReversibilityClass(meta), ReversibilityClass.IRREVERSIBLE);
  });

  test("self-asserted read_only class without registry provenance is overridden to irreversible", () => {
    const meta = { name: "read_db", reversibility_class: "read_only" };
    const normalized = normalizeReversibilityClass(meta, undefined, false);
    assert.strictEqual(normalized, ReversibilityClass.IRREVERSIBLE);
  });

  test("trusted registry-bound class is accepted", () => {
    const meta = { name: "read_db", reversibility_class: "read_only" };
    const normalized = normalizeReversibilityClass(
      meta,
      "https://creduent.idevsec.com",
      true
    );
    assert.strictEqual(normalized, ReversibilityClass.READ_ONLY);
  });

  test("vocabulary canonicalization maps alternative terms", () => {
    const guard = new ProvenanceGuard();
    const metaLocal = { name: "t1", reversibility_class: "recoverable_local" };
    const metaNonRec = { name: "t2", reversibility_class: "non_recoverable" };

    assert.strictEqual(
      guard.normalize(metaLocal, "https://creduent.idevsec.com", true),
      ReversibilityClass.REVERSIBLE
    );
    assert.strictEqual(
      guard.normalize(metaNonRec, "https://creduent.idevsec.com", true),
      ReversibilityClass.IRREVERSIBLE
    );
  });
});

describe("LedgerChainVerifier unit tests", () => {
  test("worst-case reduction across valid linked ledger receipts", async () => {
    const receipts = [
      {
        step_index: 0,
        agent_id: "agent://ns/a1",
        tool_name: "read_db",
        reversibility_class: "read_only",
        previous_receipt_hash: "GENESIS",
        provenance_source: "https://creduent.idevsec.com",
        is_registry_bound: true,
      },
      {
        step_index: 1,
        agent_id: "agent://ns/a1",
        tool_name: "update_cache",
        reversibility_class: "reversible",
        previous_receipt_hash: "38d5c671fa32b9b486b1ec92bdfca22d3fc2a3126fe531347f83cd603c0e014d",
        provenance_source: "https://creduent.idevsec.com",
        is_registry_bound: true,
      },
    ];

    const [worstCase, count] = await LedgerChainVerifier.reduceWorstCaseReversibility(receipts);
    assert.strictEqual(worstCase, ReversibilityClass.REVERSIBLE);
    assert.strictEqual(count, 2);
  });

  test("broken hash chain throws LedgerIntegrityError", async () => {
    const receipts = [
      {
        step_index: 0,
        agent_id: "agent://ns/a1",
        tool_name: "read_db",
        reversibility_class: "read_only",
        previous_receipt_hash: "GENESIS",
        provenance_source: "https://creduent.idevsec.com",
        is_registry_bound: true,
      },
      {
        step_index: 1,
        agent_id: "agent://ns/a1",
        tool_name: "delete_record",
        reversibility_class: "irreversible",
        previous_receipt_hash: "bad_hash",
        provenance_source: "https://creduent.idevsec.com",
        is_registry_bound: true,
      },
    ];

    await assert.rejects(
      async () => {
        await LedgerChainVerifier.reduceWorstCaseReversibility(receipts);
      },
      (err) => {
        return err instanceof LedgerIntegrityError && err.message.includes("Chain hash mismatch");
      }
    );
  });

  test("independent ledger truncation detection", async () => {
    const receipts = [
      {
        chain_id: "chain_123",
        step_index: 0,
        agent_id: "agent://ns/a1",
        tool_name: "read_db",
        reversibility_class: "read_only",
        previous_receipt_hash: "GENESIS",
        provenance_source: "https://creduent.idevsec.com",
        is_registry_bound: true,
      },
    ];

    const mockLedgerClient = {
      getChainMetadata: async () => ({
        chain_id: "chain_123",
        total_steps: 3,
        latest_hash: "some_hash",
      }),
    };

    await assert.rejects(
      async () => {
        await LedgerChainVerifier.reduceWorstCaseReversibility(
          receipts,
          "chain_123",
          mockLedgerClient
        );
      },
      (err) => {
        return (
          err instanceof LedgerIntegrityError &&
          err.message.includes("Chain Truncation Attack Detected")
        )
      }
    );
  });
});
