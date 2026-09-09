import assert from "node:assert";
import test from "node:test";
import { agentToDid, didToAgent, agentToDidDocument } from "../dist/esm/index.js";

test("agentToDid creduent scheme", () => {
  const agentId = "agent://idevsec/steward";
  const didUri = agentToDid(agentId, { method: "creduent" });
  assert.strictEqual(didUri, "did:creduent:idevsec:steward");
});

test("agentToDid web scheme", () => {
  const agentId = "agent://idevsec/steward";
  const didUri = agentToDid(agentId, { method: "web", domain: "idevsec.com" });
  assert.strictEqual(didUri, "did:web:idevsec.com:agent:steward");
});

test("didToAgent creduent scheme", () => {
  const didUri = "did:creduent:idevsec:steward";
  const agentId = didToAgent(didUri);
  assert.strictEqual(agentId, "agent://idevsec/steward");
});

test("didToAgent web scheme", () => {
  const didUri = "did:web:idevsec.com:agent:steward";
  const agentId = didToAgent(didUri);
  assert.strictEqual(agentId, "agent://idevsec/steward");
});

test("agentToDidDocument generation", () => {
  const agentData = {
    agent_id: "agent://idevsec/steward",
    public_key: "ed25519:7c9ab1...",
    endpoint: "https://api.idevsec.com"
  };
  const didDoc = agentToDidDocument(agentData, { method: "creduent" });

  assert.strictEqual(didDoc.id, "did:creduent:idevsec:steward");
  assert.deepStrictEqual(didDoc.alsoKnownAs, ["agent://idevsec/steward"]);
  assert.strictEqual(didDoc.verificationMethod[0].id, "did:creduent:idevsec:steward#key-1");
  assert.strictEqual(didDoc.verificationMethod[0].publicKeyMultibase, "ed25519:7c9ab1...");
  assert.strictEqual(didDoc.service[0].serviceEndpoint, "https://api.idevsec.com");
});
