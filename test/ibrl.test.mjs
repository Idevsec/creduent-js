import assert from "node:assert";
import test from "node:test";
import { IdentityRateLimiter, createExpressIBRLMiddleware } from "../dist/esm/index.js";

test("IdentityRateLimiter anonymous IP throttling", () => {
  const limiter = new IdentityRateLimiter({
    limits: { anonymous: 3, unverified: 30, verified: 600, trusted: 3000 }
  });
  const ip = "ip:127.0.0.1";

  for (let i = 0; i < 3; i++) {
    const res = limiter.checkRateLimit(ip, "anonymous");
    assert.strictEqual(res.allowed, true);
    assert.strictEqual(res.headers["X-RateLimit-Limit"], "3");
    assert.strictEqual(res.headers["X-RateLimit-Remaining"], String(2 - i));
  }

  const blocked = limiter.checkRateLimit(ip, "anonymous");
  assert.strictEqual(blocked.allowed, false);
  assert.strictEqual(blocked.headers["X-RateLimit-Remaining"], "0");
});

test("IdentityRateLimiter verified agent tier", () => {
  const limiter = new IdentityRateLimiter({
    limits: { anonymous: 2, unverified: 5, verified: 5, trusted: 10 }
  });
  const agentId = "agent://idevsec/steward";

  for (let i = 0; i < 5; i++) {
    const res = limiter.checkRateLimit(agentId, "verified");
    assert.strictEqual(res.allowed, true);
    assert.strictEqual(res.headers["X-RateLimit-Tier"], "verified");
  }

  const blocked = limiter.checkRateLimit(agentId, "verified");
  assert.strictEqual(blocked.allowed, false);
});
