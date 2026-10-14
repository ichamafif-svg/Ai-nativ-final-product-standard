// Where sessions and rate limits live: one interface (async), two stores.
//   new MemoryStore()            one process: bounded, least-recently-used entries evicted first (never a reset)
//   redisStore(client)           several instances: an ioredis or node-redis client, TLS outside localhost
// Keys are never secrets: session ids are stored by their SHA-256.
const MAX_ITEMS = 200_000;

export class MemoryStore {
  constructor(maxItems = MAX_ITEMS) { this.items = new Map(); this.max = maxItems; }

  live(key) {
    const item = this.items.get(key);
    if (!item) return undefined;
    if (item.until !== null && item.until < Date.now()) { this.items.delete(key); return undefined; }
    this.items.delete(key); this.items.set(key, item);            // most recent last
    return item.value;
  }

  put(key, value, ttlS) {
    this.items.delete(key);
    this.items.set(key, { value, until: ttlS == null ? null : Date.now() + ttlS * 1000 });
    while (this.items.size > this.max) this.items.delete(this.items.keys().next().value);
  }

  async get(key) { const v = this.live(key); return v === undefined ? null : JSON.parse(v); }
  async set(key, value, ttlS = null) { this.put(key, JSON.stringify(value), ttlS); }
  async delete(key) { this.items.delete(key); }
  async add(key, member, ttlS = null) {
    const set = new Set(JSON.parse(this.live(key) || "[]")); set.add(member);
    this.put(key, JSON.stringify([...set].sort()), ttlS);
  }
  async members(key) { return JSON.parse(this.live(key) || "[]"); }
  async discard(key, member) {
    const set = new Set(JSON.parse(this.live(key) || "[]")); set.delete(member);
    if (set.size) this.put(key, JSON.stringify([...set].sort()), null); else this.items.delete(key);
  }
  async take(key, perMinute) {
    const now = Date.now();
    let [tokens, at] = JSON.parse(this.live(key) || JSON.stringify([perMinute, now]));
    tokens = Math.min(perMinute, tokens + ((now - at) / 60000) * perMinute);
    const ok = tokens >= 1;
    this.put(key, JSON.stringify([ok ? tokens - 1 : tokens, now]), 120);
    return ok;
  }
}

const TAKE = `local v = redis.call('GET', KEYS[1])
local now, rate = tonumber(ARGV[1]), tonumber(ARGV[2])
local tokens, at = rate, now
if v then local d = cjson.decode(v); tokens, at = d[1], d[2] end
tokens = math.min(rate, tokens + (now - at) * rate / 60000)
local ok = 0
if tokens >= 1 then tokens = tokens - 1; ok = 1 end
redis.call('SET', KEYS[1], cjson.encode({tokens, now}), 'EX', 120)
return ok`;

// A store on a Redis client: `client.call(command, ...args)` (ioredis) or `client.sendCommand([...])` (node-redis).
export function redisStore(client, prefix = "standard:") {
  const run = (...args) => (client.call ? client.call(...args) : client.sendCommand(args.map(String)));
  const k = (key) => prefix + key;
  return {
    async get(key) { const v = await run("GET", k(key)); return v == null ? null : JSON.parse(v); },
    async set(key, value, ttlS = null) {
      if (ttlS == null) await run("SET", k(key), JSON.stringify(value));
      else await run("SET", k(key), JSON.stringify(value), "EX", Math.max(1, Math.floor(ttlS)));
    },
    async delete(key) { await run("DEL", k(key)); },
    async add(key, member, ttlS = null) {
      await run("SADD", k(key), member);
      if (ttlS != null) await run("EXPIRE", k(key), Math.max(1, Math.floor(ttlS)), "GT");
    },
    async members(key) { return ((await run("SMEMBERS", k(key))) || []).map(String).sort(); },
    async discard(key, member) { await run("SREM", k(key), member); },
    async take(key, perMinute) { return Number(await run("EVAL", TAKE, 1, k(key), Date.now(), perMinute)) === 1; },
  };
}

// The store for one owner: the given one, else memory, refused in production when several instances may run
// (STANDARD_INSTANCES > 1) without a shared store.
export function storeFor(given = null, env = process.env) {
  if (given) return given;
  if (env.STANDARD_ENV === "production" && Number(env.STANDARD_INSTANCES || 1) > 1) {
    throw new Error("several instances share no memory: pass a shared store (redisStore)");
  }
  return new MemoryStore();
}
