"""Redis key layout and the hot-path Lua scripts.

Authenticated-lane keys share the hash tag {t:<tool_id>} so the whole check is one
atomic script on one shard, even in Redis Cluster.
"""

# --- keys --------------------------------------------------------------------

def nonce_key(tool_id: str, nonce: str) -> str:
    return f"n:{{t:{tool_id}}}:{nonce}"


def revoked_tool_key(tool_id: str) -> str:
    return f"rv:{{t:{tool_id}}}"


def revoked_grant_key(tool_id: str, grant_id: str) -> str:
    return f"rv:{{t:{tool_id}}}:g:{grant_id}"


def grant_bucket_key(tool_id: str, grant_id: str) -> str:
    return f"b:{{t:{tool_id}}}:g:{grant_id}"


def tool_bucket_key(tool_id: str, airline_id: str) -> str:
    return f"b:{{t:{tool_id}}}:a:{airline_id}"


def grant_risk_key(tool_id: str, airline_id: str, grant_id: str) -> str:
    return f"r:{{t:{tool_id}}}:{airline_id}:g:{grant_id}"


def tool_risk_key(tool_id: str, airline_id: str) -> str:
    return f"r:{{t:{tool_id}}}:{airline_id}:tool"


def ip_bucket_key(airline_id: str, ip: str) -> str:
    return f"b:{{ip:{ip}}}:{airline_id}"


def device_bucket_key(airline_id: str, device_ref: str) -> str:
    return f"b:{{d:{device_ref}}}:{airline_id}"


def ip_risk_key(airline_id: str, ip: str) -> str:
    return f"r:{{ip:{ip}}}:{airline_id}"


def device_risk_key(airline_id: str, device_ref: str) -> str:
    return f"r:{{d:{device_ref}}}:{airline_id}"


CONFIG_CHANNEL = "ffpv:config"
RISK_TTL_MS = 15 * 60 * 1000
BUCKET_TTL_MS = 5 * 60 * 1000

# --- scripts -----------------------------------------------------------------

_BUCKET_FN = """
local function refill(key, rate, cap, now)
  local b = redis.call('HMGET', key, 't', 'ts')
  local tokens, ts = tonumber(b[1]), tonumber(b[2])
  if tokens == nil then return cap end
  return math.min(cap, tokens + math.max(0, now - ts) * rate)
end
"""

# KEYS: nonce, revoked_tool, revoked_grant, grant_bucket, tool_bucket, grant_risk, tool_risk
# ARGV: nonce_ttl_s, now_ms, grant_rate_per_ms, grant_cap, tool_rate_per_ms, tool_cap, bucket_ttl_ms
# -> {status, retry_ms, grant_score, grant_reasons, tool_score, tool_reasons}  ('' when absent: a Lua
#    false/nil would truncate the reply array)
AUTH_SCRIPT = _BUCKET_FN + """
if not redis.call('SET', KEYS[1], '1', 'NX', 'EX', tonumber(ARGV[1])) then
  return {'replay', '0'}
end
local rt = redis.call('GET', KEYS[2])
if rt then return {'revoked_tool', '0', rt} end
local rg = redis.call('GET', KEYS[3])
if rg then return {'revoked_grant', '0', rg} end

local now = tonumber(ARGV[2])
local r1, c1, r2, c2 = tonumber(ARGV[3]), tonumber(ARGV[4]), tonumber(ARGV[5]), tonumber(ARGV[6])
local t1 = refill(KEYS[4], r1, c1, now)
local t2 = refill(KEYS[5], r2, c2, now)
local status, retry = 'ok', 0
if t1 < 1 then
  status, retry = 'rate_credential', math.ceil((1 - t1) / r1)
elseif t2 < 1 then
  status, retry = 'rate_tool', math.ceil((1 - t2) / r2)
else
  t1, t2 = t1 - 1, t2 - 1
end
redis.call('HSET', KEYS[4], 't', tostring(t1), 'ts', ARGV[2])
redis.call('PEXPIRE', KEYS[4], tonumber(ARGV[7]))
redis.call('HSET', KEYS[5], 't', tostring(t2), 'ts', ARGV[2])
redis.call('PEXPIRE', KEYS[5], tonumber(ARGV[7]))
local g = redis.call('HMGET', KEYS[6], 's', 'r')
local t = redis.call('HMGET', KEYS[7], 's', 'r')
return {status, tostring(retry), g[1] or '', g[2] or '', t[1] or '', t[2] or ''}
"""

# KEYS: client_bucket (device, or the IP bucket again), ip_bucket, ip_risk, device_risk (or ip_risk again)
# ARGV: now_ms, client_rate, client_cap, ip_rate, ip_cap, has_device (0/1), bucket_ttl_ms
# -> {status, retry_ms, ip_score, ip_reasons, device_score, device_reasons}  ('' when absent)
# One script = one round trip (a redis-py pipeline containing a script adds a SCRIPT EXISTS call).
# Not hash-tagged: device and IP keys live on different slots in Redis Cluster, which is
# fine for a standalone/replicated Redis; shard by airline if you need Cluster here.
UNAUTH_SCRIPT = _BUCKET_FN + """
local now = tonumber(ARGV[1])
local r1, c1, r2, c2 = tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4]), tonumber(ARGV[5])
local has_device = ARGV[6] == '1'
local status, retry = 'ok', 0
local t1 = refill(KEYS[1], r1, c1, now)
local t2 = t1
if has_device then t2 = refill(KEYS[2], r2, c2, now) end
if t1 < 1 then
  status, retry = has_device and 'rate_client' or 'rate_ip', math.ceil((1 - t1) / r1)
elseif t2 < 1 then
  status, retry = 'rate_ip', math.ceil((1 - t2) / r2)
else
  t1, t2 = t1 - 1, t2 - 1
end
redis.call('HSET', KEYS[1], 't', tostring(t1), 'ts', ARGV[1])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[7]))
if has_device then
  redis.call('HSET', KEYS[2], 't', tostring(t2), 'ts', ARGV[1])
  redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[7]))
end
local ip = redis.call('HMGET', KEYS[3], 's', 'r')
local dev = {false, false}
if has_device then dev = redis.call('HMGET', KEYS[4], 's', 'r') end
return {status, tostring(retry), ip[1] or '', ip[2] or '', dev[1] or '', dev[2] or ''}
"""


def bucket_params(limit_per_min: float, burst_multiplier: float) -> tuple[float, float]:
    """Token bucket refilling at the per-minute limit, holding ~10s of traffic x burst."""
    rate_per_ms = limit_per_min / 60_000
    cap = max(2.0, limit_per_min / 6 * burst_multiplier)
    return rate_per_ms, cap
