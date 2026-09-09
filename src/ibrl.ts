/*
 * Copyright 2026 IDevSec
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export type IdentityTier = "anonymous" | "unverified" | "verified" | "trusted";

export interface IBRLOptions {
  limits?: Record<IdentityTier, number>;
  windowSeconds?: number;
}

export interface RateLimitCheckResult {
  allowed: boolean;
  tier: IdentityTier;
  identifier: string;
  limit: number;
  remaining: number;
  reset: number;
  headers: Record<string, string>;
}

const DEFAULT_LIMITS: Record<IdentityTier, number> = {
  anonymous: 10,
  unverified: 30,
  verified: 600,
  trusted: 3000,
};

const DEFAULT_WINDOW_SECONDS = 60;

export class IdentityRateLimiter {
  private limits: Record<IdentityTier, number>;
  private windowMs: number;
  private memoryStore: Map<string, number[]>;

  constructor(options: IBRLOptions = {}) {
    this.limits = { ...DEFAULT_LIMITS, ...options.limits };
    this.windowMs = (options.windowSeconds || DEFAULT_WINDOW_SECONDS) * 1000;
    this.memoryStore = new Map<string, number[]>();
  }

  public checkRateLimit(
    identifier: string,
    tier: IdentityTier = "anonymous"
  ): RateLimitCheckResult {
    const activeTier: IdentityTier = this.limits[tier] ? tier : "anonymous";
    const limit = this.limits[activeTier];
    const now = Date.now();
    const windowStart = now - this.windowMs;

    let timestamps = this.memoryStore.get(identifier) || [];
    timestamps = timestamps.filter((ts) => ts > windowStart);

    const allowed = timestamps.length < limit;
    if (allowed) {
      timestamps.push(now);
    }

    this.memoryStore.set(identifier, timestamps);

    const remaining = Math.max(0, limit - timestamps.length);
    const oldestTs = timestamps[0] || now;
    const reset = Math.ceil((oldestTs + this.windowMs) / 1000);

    const headers: Record<string, string> = {
      "X-Creduent-Agent-ID": identifier,
      "X-RateLimit-Limit": String(limit),
      "X-RateLimit-Remaining": String(remaining),
      "X-RateLimit-Reset": String(reset),
      "X-RateLimit-Tier": activeTier,
    };

    return {
      allowed,
      tier: activeTier,
      identifier,
      limit,
      remaining,
      reset,
      headers,
    };
  }

  public clear(): void {
    this.memoryStore.clear();
  }
}

/**
  Creates Express-compatible middleware for Identity-Based Rate Limiting.
 */
export function createExpressIBRLMiddleware(limiter?: IdentityRateLimiter) {
  const activeLimiter = limiter || new IdentityRateLimiter();

  return (req: any, res: any, next: any) => {
    const agentId = (req.headers["x-creduent-agent-id"] as string) || "";
    const signature = (req.headers["x-creduent-signature"] as string) || "";
    const authHeader = (req.headers["authorization"] as string) || "";
    const clientIp = req.ip || req.socket?.remoteAddress || "127.0.0.1";

    let tier: IdentityTier = "anonymous";
    let identifier = `ip:${clientIp}`;

    if (agentId) {
      identifier = agentId;
      if (signature || authHeader) {
        tier = "verified";
      } else {
        tier = "unverified";
      }
    }

    const result = activeLimiter.checkRateLimit(identifier, tier);

    Object.entries(result.headers).forEach(([k, v]) => {
      res.setHeader(k, v);
    });

    if (!result.allowed) {
      const retryAfter = Math.max(1, result.reset - Math.floor(Date.now() / 1000));
      res.setHeader("Retry-After", String(retryAfter));
      return res.status(429).json({
        error: "rate_limit_exceeded",
        message: `Rate limit exceeded for ${identifier}. Retry after ${retryAfter} seconds.`,
        agent_id: identifier,
        retry_after: retryAfter,
      });
    }

    next();
  };
}
