"""Async risk worker: event stream -> windowed features -> scores (Redis) + history (Postgres).

Runs off the hot path. Each batch:
  1. updates sliding-window features in Redis (event time, so simulations can run fast),
  2. rescores every grant / tool / IP / device the batch touched,
  3. writes scores + reasons where the verifier reads them, auto-revokes grants past the
     airline's revoke threshold,
  4. persists search_requests / risk_events / grants / credentials to Postgres.
"""

import asyncio
import logging
import os
import socket
from collections import defaultdict
from datetime import datetime, timezone

import asyncpg
import orjson
import redis.asyncio as aioredis

from .. import store
from ..config import Settings, get_settings
from ..db import create_pool, migrate
from ..policy import AirlinePolicy
from ..registry import Registry
from ..tokens import TokenVerifier
from .scorer import AuthFeatures, RiskResult, UnauthFeatures, score_authenticated, score_unauthenticated

log = logging.getLogger(__name__)

MIN_1 = 60_000
MIN_5 = 5 * MIN_1
MIN_10 = 10 * MIN_1
FEATURE_TTL_MS = 30 * MIN_1
MEMBER_TOOLS_TTL_S = 30 * 24 * 3600


def _dt(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)


# Feature keys (worker-owned).
def k_vel(scope: str, airline: str, ident: str) -> str: return f"f:v:{airline}:{scope}:{ident}"
def k_ips(scope: str, ident: str) -> str: return f"f:ips:{scope}:{ident}"
def k_ipchg(scope: str, ident: str) -> str: return f"f:ipc:{scope}:{ident}"
def k_lastip(scope: str, ident: str) -> str: return f"f:lip:{scope}:{ident}"
def k_member_tools(airline: str, member: str) -> str: return f"f:mt:{airline}:{member}"
def k_grant_first_seen(grant: str) -> str: return f"f:gfs:{grant}"
def k_tool_fail(tool: str) -> str: return f"f:vf:{tool}"
def k_ip_airlines(ip: str) -> str: return f"f:air:{ip}"
def k_ip_devices(ip: str) -> str: return f"f:idv:{ip}"


class RiskWorker:
    def __init__(self, redis: aioredis.Redis, pool: asyncpg.Pool | None, policies: dict, settings: Settings,
                 persist: bool = True):
        self.redis = redis
        self.pool = pool
        self.policies = policies  # airline_id -> PolicyRecord (shared with a Registry)
        self.s = settings
        self.persist = persist and pool is not None
        self.group = "risk"
        self.consumer = f"{socket.gethostname()}-{os.getpid()}"

    def policy(self, airline_id: str) -> AirlinePolicy:
        rec = self.policies.get(airline_id)
        return rec.policy if rec else AirlinePolicy()

    # --- feature updates ---------------------------------------------------------

    async def process_batch(self, events: list[dict]) -> dict:
        if not events:
            return {}
        events.sort(key=lambda e: e["ts"])
        now = events[-1]["ts"]
        r = self.redis

        # Last-known IP per grant/device, to count IP changes in order.
        idents = {("g", e["grant_id"]) for e in events if e.get("grant_id")}
        idents |= {("d", e["device_ref"]) for e in events if e.get("device_ref")}
        idents_l = sorted(idents)
        last_ip = dict(zip(idents_l, await r.mget([k_lastip(s, i) for s, i in idents_l]))) if idents_l else {}
        last_ip = {k: (v.decode() if v else None) for k, v in last_ip.items()}

        grants: dict[tuple, dict] = {}
        tools_failed: set[tuple[str, str]] = set()
        ips: set[tuple[str, str]] = set()
        devices: set[tuple[str, str]] = set()

        pipe = r.pipeline(transaction=False)
        for e in events:
            ts, airline, rid, ip = e["ts"], e["airline_id"], e["request_id"], e["ip"]
            if e["lane"] == "authenticated":
                if e.get("attributable") and e.get("tool_id"):
                    pipe.zadd(k_tool_fail(e["tool_id"]), {rid: ts})
                    tools_failed.add((e["tool_id"], airline))
                grant = e.get("grant_id")
                if not grant or e.get("failure"):
                    # Only authenticated requests describe the grant's behavior. Blocked ones (replays from
                    # other IPs, revoked, ...) could be someone else's traffic carrying this grant's identity.
                    continue
                grants[(airline, e["tool_id"], grant)] = e
                pipe.zadd(k_vel("g", airline, grant), {rid: ts})
                pipe.zadd(k_ips("g", grant), {ip: ts})
                prev = last_ip.get(("g", grant))
                if prev is not None and prev != ip:
                    pipe.zadd(k_ipchg("g", grant), {f"{ts}:{ip}": ts})
                last_ip[("g", grant)] = ip
                pipe.set(k_grant_first_seen(grant), ts, nx=True, px=MEMBER_TOOLS_TTL_S * 1000)
                if e.get("member_ref"):
                    mt = k_member_tools(airline, e["member_ref"])
                    pipe.sadd(mt, e["tool_id"])
                    pipe.expire(mt, MEMBER_TOOLS_TTL_S)
            else:
                ips.add((airline, ip))
                pipe.zadd(k_vel("ip", airline, ip), {rid: ts})
                pipe.zadd(k_ip_airlines(ip), {airline: ts})
                dev = e.get("device_ref")
                if dev:
                    pipe.zadd(k_ip_devices(ip), {dev: ts})
                    devices.add((airline, dev))
                    pipe.zadd(k_vel("d", airline, dev), {rid: ts})
                    prev = last_ip.get(("d", dev))
                    if prev is not None and prev != ip:
                        pipe.zadd(k_ipchg("d", dev), {f"{ts}:{ip}": ts})
                    last_ip[("d", dev)] = ip
        for (scope, ident), ip in last_ip.items():
            if ip:
                pipe.set(k_lastip(scope, ident), ip, px=FEATURE_TTL_MS)
        await pipe.execute()

        # --- read windowed features for everything touched -------------------------
        pipe = r.pipeline(transaction=False)
        grant_keys = list(grants)
        for airline, tool, grant in grant_keys:
            e = grants[(airline, tool, grant)]
            for key, window in ((k_vel("g", airline, grant), MIN_1), (k_ipchg("g", grant), MIN_5),
                                (k_ips("g", grant), MIN_5)):
                pipe.zremrangebyscore(key, 0, now - window)
                pipe.pexpire(key, FEATURE_TTL_MS)
            pipe.zcount(k_vel("g", airline, grant), now - MIN_1, "+inf")
            pipe.zcount(k_ipchg("g", grant), now - MIN_5, "+inf")
            pipe.zcount(k_ips("g", grant), now - MIN_1, "+inf")
            pipe.scard(k_member_tools(airline, e["member_ref"])) if e.get("member_ref") else pipe.echo("0")
            pipe.get(k_grant_first_seen(grant))
        tool_keys = sorted(tools_failed)
        for tool, _airline in tool_keys:
            pipe.zremrangebyscore(k_tool_fail(tool), 0, now - MIN_5)
            pipe.pexpire(k_tool_fail(tool), FEATURE_TTL_MS)
            pipe.zcount(k_tool_fail(tool), now - MIN_5, "+inf")
        ip_keys = sorted(ips)
        for airline, ip in ip_keys:
            pipe.zremrangebyscore(k_vel("ip", airline, ip), 0, now - MIN_1)
            pipe.pexpire(k_vel("ip", airline, ip), FEATURE_TTL_MS)
            pipe.zremrangebyscore(k_ip_airlines(ip), 0, now - MIN_10)
            pipe.pexpire(k_ip_airlines(ip), FEATURE_TTL_MS)
            pipe.zremrangebyscore(k_ip_devices(ip), 0, now - MIN_10)
            pipe.pexpire(k_ip_devices(ip), FEATURE_TTL_MS)
            pipe.zcount(k_vel("ip", airline, ip), now - MIN_1, "+inf")
            pipe.zcount(k_ip_airlines(ip), now - MIN_10, "+inf")
            pipe.zcount(k_ip_devices(ip), now - MIN_10, "+inf")
        dev_keys = sorted(devices)
        for airline, dev in dev_keys:
            for key, window in ((k_vel("d", airline, dev), MIN_1), (k_ipchg("d", dev), MIN_5)):
                pipe.zremrangebyscore(key, 0, now - window)
                pipe.pexpire(key, FEATURE_TTL_MS)
            pipe.zcount(k_vel("d", airline, dev), now - MIN_1, "+inf")
            pipe.zcount(k_ipchg("d", dev), now - MIN_5, "+inf")
        res = iter(await pipe.execute())

        out_pipe = r.pipeline(transaction=False)
        scored: dict = {"grants": {}, "tools": {}, "ips": {}, "devices": {}}
        revocations = []

        for airline, tool, grant in grant_keys:
            for _ in range(6):
                next(res)
            vel, ipchg, ips60, n_tools, first_seen = (next(res) for _ in range(5))
            e = grants[(airline, tool, grant)]
            p = self.policy(airline)
            start_ms = e["auth_time"] * 1000 if e.get("auth_time") else int(first_seen or now)
            f = AuthFeatures(
                searches_last_60s=int(vel), effective_limit_per_min=e.get("effective_limit")
                or p.max_searches_per_min_per_credential,
                ip_changes_5m=int(ipchg), distinct_ips_60s=int(ips60), grant_age_s=max(0, now - start_ms) / 1000,
                tools_for_member=int(n_tools) if e.get("member_ref") else None)
            result = score_authenticated(f, p)
            self._write_risk(out_pipe, store.grant_risk_key(tool, airline, grant), result)
            scored["grants"][grant] = (result, e)
            if result.score >= p.thresholds.revoke:
                reason = "auto-revoked: " + "; ".join(c.detail for c in result.contributions[:2])
                out_pipe.set(store.revoked_grant_key(tool, grant), reason)
                revocations.append((airline, tool, grant, result, reason, e))

        for tool, airline in tool_keys:
            for _ in range(2):
                next(res)
            fails = int(next(res))
            result = score_authenticated(AuthFeatures(attributable_failures_5m=fails), self.policy(airline))
            self._write_risk(out_pipe, store.tool_risk_key(tool, airline), result)
            scored["tools"][(tool, airline)] = result

        for airline, ip in ip_keys:
            for _ in range(6):
                next(res)
            vel, n_air, n_dev = int(next(res)), int(next(res)), int(next(res))
            p = self.policy(airline)
            # Many distinct first-party devices behind one IP = shared address; scale the IP's allowance.
            clients = max(1, min(n_dev, p.max_devices_per_ip))
            result = score_unauthenticated(UnauthFeatures(
                searches_last_60s=vel, limit_per_min=p.max_searches_per_min_per_ip_unauthenticated * clients,
                airlines_10m=n_air, airlines_keyed_by="ip"), p)
            self._write_risk(out_pipe, store.ip_risk_key(airline, ip), result)
            scored["ips"][(airline, ip)] = result

        for airline, dev in dev_keys:
            for _ in range(4):
                next(res)
            vel, ipchg = int(next(res)), int(next(res))
            p = self.policy(airline)
            result = score_unauthenticated(UnauthFeatures(
                searches_last_60s=vel, limit_per_min=p.max_searches_per_min_per_ip_unauthenticated,
                ip_changes_5m=ipchg), p)
            self._write_risk(out_pipe, store.device_risk_key(airline, dev), result)
            scored["devices"][(airline, dev)] = result

        await out_pipe.execute()
        if self.persist:
            await self._persist(events, scored, revocations)
        return scored

    @staticmethod
    def _write_risk(pipe, key: str, result: RiskResult) -> None:
        pipe.hset(key, mapping={"s": f"{result.score:.2f}", "r": orjson.dumps(result.reasons())})
        pipe.pexpire(key, store.RISK_TTL_MS)

    # --- persistence ---------------------------------------------------------------

    async def _persist(self, events: list[dict], scored: dict, revocations: list) -> None:
        search_rows, risk_rows = [], []
        creds: dict[str, dict] = {}
        for e in events:
            search_rows.append((
                _dt(e["ts"]), e["request_id"], e["airline_id"], e["lane"], e.get("tool_id"), e.get("grant_id"),
                e.get("jti"), e["ip"], e.get("device_ref"), e.get("origin"), e.get("destination"),
                _parse_date(e.get("date")), e.get("cabin"), e["decision"], e["score"], e.get("reason_codes") or [],
                e["latency_us"], {k: e.get(k) for k in ("failure", "dc", "effective_limit")},
            ))
            if e["decision"] != "allow":
                subj = ("grant", e["grant_id"]) if e.get("grant_id") else \
                    ("tool", e.get("tool_id") or e.get("claimed_tool_id")) if e["lane"] == "authenticated" \
                    else ("device", e["device_ref"]) if e.get("device_ref") else ("ip", e["ip"])
                risk_rows.append((_dt(e["ts"]), e["request_id"], e["airline_id"], e["lane"], subj[0],
                                  subj[1] or "unknown", e["score"],
                                  {"reason_codes": e.get("reason_codes"), "failure": e.get("failure")},
                                  e["decision"]))
            if e.get("jti") and e.get("grant_id") and not e.get("failure"):
                c = creds.setdefault(e["jti"], {"e": e, "n": 0, "ips": set(), "first": e["ts"], "last": e["ts"]})
                c["n"] += 1
                c["ips"].add(e["ip"])
                c["last"] = e["ts"]
        for airline, tool, grant, result, reason, e in revocations:
            risk_rows.append((_dt(e["ts"]), e["request_id"], airline, "authenticated", "grant", grant, result.score,
                              {"reasons": result.reasons(), "detail": reason}, "revoke"))

        grant_rows = [(g, e["tool_id"], e["airline_id"], e["member_ref"],
                       _dt(e["auth_time"] * 1000) if e.get("auth_time") else None, _dt(e["ts"]), result.score)
                      for g, (result, e) in scored["grants"].items()]
        cred_rows = [(jti, c["e"]["grant_id"], c["e"]["tool_id"], c["e"]["airline_id"], _dt(c["e"]["iat"] * 1000),
                      _dt(c["e"]["exp"] * 1000), c["e"].get("routes"), _dt(c["first"]), _dt(c["last"]), c["n"],
                      sorted(c["ips"]))
                     for jti, c in creds.items()]
        tool_scores: dict[str, float] = defaultdict(float)
        tool_seen: dict[str, int] = {}
        for result, e in scored["grants"].values():
            tool_scores[e["tool_id"]] = max(tool_scores[e["tool_id"]], result.score)
        for e in events:
            if e.get("tool_id") and e["lane"] == "authenticated":
                tool_seen[e["tool_id"]] = e["ts"]

        async with self.pool.acquire() as conn, conn.transaction():
            await conn.copy_records_to_table("search_requests", records=search_rows, columns=[
                "ts", "request_id", "airline_id", "lane", "tool_id", "grant_id", "cred_id", "client_ip", "device_ref",
                "origin", "destination", "travel_date", "cabin", "decision", "score", "reason_codes",
                "verify_latency_us", "risk_signals"])
            if grant_rows:
                await conn.executemany("""
                    INSERT INTO grants (grant_id, tool_id, airline_id, member_ref, auth_time, first_seen, last_seen,
                                        risk_score)
                    VALUES ($1, $2, $3, $4, $5, $6, $6, $7)
                    ON CONFLICT (grant_id) DO UPDATE SET last_seen = GREATEST(grants.last_seen, EXCLUDED.last_seen),
                        auth_time = COALESCE(EXCLUDED.auth_time, grants.auth_time), risk_score = EXCLUDED.risk_score
                """, grant_rows)
            if cred_rows:
                await conn.executemany("""
                    INSERT INTO credentials (cred_id, grant_id, tool_id, airline_id, issued_at, expires_at,
                                             route_scope, first_seen, last_seen, usage_count, ip_history)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::inet[])
                    ON CONFLICT (cred_id) DO UPDATE SET
                        last_seen = GREATEST(credentials.last_seen, EXCLUDED.last_seen),
                        usage_count = credentials.usage_count + EXCLUDED.usage_count,
                        ip_history = (SELECT ARRAY(SELECT DISTINCT unnest(credentials.ip_history || EXCLUDED.ip_history)
                                                   LIMIT 32))
                """, cred_rows)
            if risk_rows:
                await conn.executemany("""
                    INSERT INTO risk_events (ts, request_id, airline_id, lane, subject_type, subject_id, risk_score,
                                             flags, action_taken)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """, risk_rows)
            for airline, tool, grant, result, reason, e in revocations:
                await conn.execute("UPDATE grants SET status = 'revoked', status_reason = $2 WHERE grant_id = $1",
                                   grant, reason)
            if tool_seen:
                await conn.executemany(
                    "UPDATE authorized_tools SET last_seen = GREATEST(last_seen, $2), risk_score = $3 WHERE tool_id = $1",
                    [(t, _dt(ts), tool_scores.get(t, 0.0)) for t, ts in tool_seen.items()])

    # --- stream consumption ----------------------------------------------------------

    async def run(self) -> None:
        stream = self.s.events_stream
        try:
            await self.redis.xgroup_create(stream, self.group, id="0", mkstream=True)
        except aioredis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise
        log.info("risk worker %s consuming %s", self.consumer, stream)
        while True:
            resp = await self.redis.xreadgroup(self.group, self.consumer, {stream: ">"}, count=2000, block=200)
            if not resp:
                continue
            for _stream, entries in resp:
                ids = [eid for eid, _ in entries]
                events = [orjson.loads(fields[b"e"]) for _, fields in entries]
                try:
                    await self.process_batch(events)
                except Exception:
                    log.exception("batch of %d events failed; acking to avoid a poison loop", len(events))
                await self.redis.xack(stream, self.group, *ids)


def _parse_date(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError:
        return None


async def _main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    s = get_settings()
    pool = await create_pool(s.database_url)
    await migrate(pool)
    redis = aioredis.from_url(s.redis_url)
    registry = Registry(pool, redis, TokenVerifier(s.token_audience, s.clock_skew_s, s.max_token_lifetime_s))
    await registry.load_all()
    registry.start()
    await RiskWorker(redis, pool, registry.policies, s).run()


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
