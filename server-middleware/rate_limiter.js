/**
 * rate_limiter.js
 * ---------------------------------------------------------------
 * Echte token-bucket rate limiter als Express middleware.
 * Dit hoort SERVERSIDE te draaien — client-side rate limiting kan
 * altijd omzeild worden (de gebruiker bestuurt de client).
 *
 * Werking:
 *   - Elke client (op basis van sleutel — zie keyFn) krijgt een
 *     "bucket" met een maximum aantal tokens.
 *   - Elk verzoek kost 1 token.
 *   - Tokens worden continu bijgevuld met refillRate per seconde,
 *     tot het maximum (capacity).
 *   - Is de bucket leeg, dan krijgt de client een 429.
 *
 * Dit is bewust gedrag-gebaseerd i.p.v. puur IP-gebaseerd: je kunt
 * de keyFn aanpassen om te combineren met een API-key, user-id,
 * of een fingerprint-hash — zodat NAT-gebruikers achter hetzelfde
 * IP niet onterecht worden geblokkeerd, en een enkele agressieve
 * client niet zomaar van IP kan wisselen om te ontsnappen.
 *
 * Installatie:
 *   npm install express
 *
 * Gebruik:
 *   const { rateLimiter } = require('./rate_limiter');
 *   app.use(rateLimiter({ capacity: 20, refillRate: 5 }));
 *
 *   // Of specifiek op een route:
 *   app.post('/api/generate', rateLimiter({ capacity: 5, refillRate: 1 }), handler);
 * ---------------------------------------------------------------
 */

'use strict';

/**
 * In-memory bucket store. Voor een multi-instance deployment
 * (meerdere Node-processen achter een load balancer) vervang je
 * dit door Redis (zie redisStoreExample onderaan) zodat alle
 * instances dezelfde bucket-state delen.
 */
class MemoryBucketStore {
  constructor() {
    this.buckets = new Map();
    // Ruim oude, inactieve buckets periodiek op om geheugenlek te voorkomen.
    this._gc = setInterval(() => this._cleanup(), 10 * 60 * 1000);
    this._gc.unref?.();
  }

  _cleanup() {
    const now = Date.now();
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.lastSeen > 30 * 60 * 1000) {
        this.buckets.delete(key);
      }
    }
  }

  get(key, capacity) {
    if (!this.buckets.has(key)) {
      this.buckets.set(key, {
        tokens: capacity,
        lastRefill: Date.now(),
        lastSeen: Date.now(),
      });
    }
    return this.buckets.get(key);
  }
}

const defaultStore = new MemoryBucketStore();

/**
 * @param {Object} opts
 * @param {number} opts.capacity   Max tokens in de bucket (burst-grootte). Default 20.
 * @param {number} opts.refillRate Tokens per seconde die worden bijgevuld. Default 5.
 * @param {Function} opts.keyFn    (req) => string, bepaalt welke bucket bij dit verzoek hoort.
 *                                  Default: IP-adres.
 * @param {Object} opts.store      Bucket-store (default: in-memory). Geef een Redis-store
 *                                  door voor multi-instance deployments.
 * @param {Function} opts.onLimited (req, res) => void, custom handler bij overschrijding.
 */
function rateLimiter(opts = {}) {
  const capacity = opts.capacity ?? 20;
  const refillRate = opts.refillRate ?? 5; // tokens/sec
  const store = opts.store ?? defaultStore;
  const keyFn = opts.keyFn ?? ((req) => req.ip || req.connection?.remoteAddress || 'unknown');

  return function rateLimiterMiddleware(req, res, next) {
    const key = keyFn(req);
    const bucket = store.get(key, capacity);

    const now = Date.now();
    const elapsedSec = (now - bucket.lastRefill) / 1000;
    bucket.tokens = Math.min(capacity, bucket.tokens + elapsedSec * refillRate);
    bucket.lastRefill = now;
    bucket.lastSeen = now;

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;

      res.setHeader('X-RateLimit-Limit', capacity);
      res.setHeader('X-RateLimit-Remaining', Math.floor(bucket.tokens));

      return next();
    }

    // Bucket leeg -> blokkeren
    const retryAfterSec = Math.max(1, Math.ceil((1 - bucket.tokens) / refillRate));
    res.setHeader('Retry-After', retryAfterSec);
    res.setHeader('X-RateLimit-Limit', capacity);
    res.setHeader('X-RateLimit-Remaining', 0);

    if (opts.onLimited) {
      return opts.onLimited(req, res);
    }

    return res.status(429).json({
      error: 'too_many_requests',
      message: `Rate limit overschreden. Probeer het over ${retryAfterSec}s opnieuw.`,
      retry_after_seconds: retryAfterSec,
    });
  };
}

/**
 * Voorbeeld van een Redis-backed store voor multi-instance deployments.
 * Vereist: npm install ioredis
 *
 * Gebruikt een Lua-script zodat de read-modify-write van tokens atomisch
 * gebeurt, ook onder gelijktijdige requests.
 */
/*
const Redis = require('ioredis');

class RedisBucketStore {
  constructor(redisUrl) {
    this.redis = new Redis(redisUrl);
    this.script = `
      local key = KEYS[1]
      local capacity = tonumber(ARGV[1])
      local refillRate = tonumber(ARGV[2])
      local now = tonumber(ARGV[3])

      local data = redis.call('HMGET', key, 'tokens', 'lastRefill')
      local tokens = tonumber(data[1])
      local lastRefill = tonumber(data[2])

      if tokens == nil then
        tokens = capacity
        lastRefill = now
      end

      local elapsed = (now - lastRefill) / 1000
      tokens = math.min(capacity, tokens + elapsed * refillRate)
      lastRefill = now

      local allowed = 0
      if tokens >= 1 then
        tokens = tokens - 1
        allowed = 1
      end

      redis.call('HMSET', key, 'tokens', tokens, 'lastRefill', lastRefill)
      redis.call('EXPIRE', key, 1800)

      return {allowed, tokens}
    `;
  }

  async consume(key, capacity, refillRate) {
    const now = Date.now();
    const [allowed, tokens] = await this.redis.eval(
      this.script, 1, `ratelimit:${key}`, capacity, refillRate, now
    );
    return { allowed: allowed === 1, tokens };
  }
}
*/

module.exports = { rateLimiter, MemoryBucketStore };
