"""The hot path: one call per airline search request.

Budget: crypto (~0.2ms) + one Redis round trip (~0.5ms) + in-memory policy. No Postgres,
no model inference. Behavioral scoring happens in the worker; its latest score for this
grant / IP / device is read back from Redis and folded in here.
"""

import asyncio
import base64
import hashlib
import time
import uuid
from dataclasses import dataclass, field

import orjson
import redis.asyncio as aioredis
from prometheus_client import Counter, Histogram

from . import httpsig, store
from .config import Settings
from .events import EventBuffer
from .ipintel import StaticIpIntel
from .models import Decision, Lane, Reason, VerifyRequest, VerifyResponse
from .policy import AirlinePolicy, FailMode, Thresholds, UnauthenticatedMode, VpnTolerance
from .registry import Registry
from .risk import pillars
from .risk.scorer import (Contribution, UnauthFeatures, combine, evidence, evidence_from_score,
                          automation_strength, score_unauthenticated)
from .tokens import TokenError

VERIFY_LATENCY = Histogram("ffpv_verify_latency_seconds", "Verification latency", ["lane"],
                           buckets=(0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25))
DECISIONS = Counter("ffpv_decisions_total", "Verification decisions", ["airline", "lane", "decision"])
DEGRADED = Counter("ffpv_degraded_total", "Decisions made without Redis", ["airline"])
LATE_REDIS = Counter("ffpv_redis_over_budget_total", "Redis calls that exceeded the hot-path budget")

# Failures that only someone holding the tool's private key could cause. Anything
# before a valid signature (bad signature, unknown key) can be forged by a third party
# using the tool's public keyid, so it must never count against the tool.
# Replays are excluded too: resending a captured request is exactly what a third party does.
ATTRIBUTABLE = {"key_mismatch", "client_mismatch", "route_not_authorized", "wrong_airline",
                "token_expired", "insufficient_scope"}

SHARED_IP_DISCOUNT = 0.25

BLOCK_MESSAGES = {
    "unknown_key": "Signature keyid is not a registered tool key.",
    "tool_revoked": "This tool's key has been revoked.",
    "grant_revoked": "This member's authorization of the tool has been revoked.",
    "key_mismatch": "Access token is bound to a different key than the one that signed the request.",
    "client_mismatch": "Access token was issued to a different tool.",
    "route_not_authorized": "The member's authorization does not cover this route.",
    "replay": "Signature nonce was already used.",
    "agents_not_permitted": "This airline does not accept automated searches, even when authorized.",
    "vpn_not_permitted": "This airline does not accept searches from datacenter / VPN addresses.",
    "missing_signature": "Authorization header present but the request is not signed.",
    "missing_token": "Signed request without a Bearer access token.",
}


@dataclass
class Outcome:
    decision: Decision
    lane: Lane
    score: float = 0.0
    reasons: list[dict] = field(default_factory=list)
    tool_id: str | None = None
    retry_after_s: int | None = None
    degraded: bool = False
    failure: str | None = None
    attributable: bool = False
    pillars: dict[str, float] | None = None


def decide(score: float, lane: Lane, th: Thresholds) -> Decision:
    if score >= th.block:
        return Decision.block
    if score >= th.throttle:
        return Decision.throttle
    if score >= th.challenge:
        return Decision.flag if lane is Lane.authenticated else Decision.challenge
    return Decision.allow


def _block(lane: Lane, code: str, message: str | None = None, **kw) -> Outcome:
    return Outcome(Decision.block, lane, 100.0,
                   [{"signal": code, "detail": message or BLOCK_MESSAGES.get(code, code), "advice": ""}],
                   pillars=pillars.hard_block(code), **kw)


def _cached_reasons(raw) -> list[dict]:
    if not raw:
        return []
    try:
        return orjson.loads(raw)
    except orjson.JSONDecodeError:
        return []


class Verifier:
    def __init__(self, settings: Settings, registry: Registry, redis: aioredis.Redis, events: EventBuffer,
                 ipintel: StaticIpIntel | None = None):
        self.s = settings
        self.registry = registry
        self.redis = redis
        self.events = events
        self.ipintel = ipintel or StaticIpIntel()
        self._auth_script = redis.register_script(store.AUTH_SCRIPT)
        self._unauth_script = redis.register_script(store.UNAUTH_SCRIPT)

    async def verify(self, req: VerifyRequest, airline_id: str, now_ms: int | None = None) -> VerifyResponse:
        t0 = time.perf_counter()
        now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
        prec = self.registry.policies[airline_id]
        policy = prec.policy
        headers = {k.lower(): v for k, v in req.request.headers.items()}
        is_dc = self.ipintel.lookup(req.client_ip).is_datacenter
        ctx: dict = {}

        if "signature-input" in headers or headers.get("authorization", "").lower().startswith("bearer "):
            out = await self._authenticated(req, headers, airline_id, policy, now_ms, is_dc, ctx)
        else:
            out = await self._unauthenticated(req, headers, airline_id, policy, now_ms, is_dc, ctx)

        latency_us = int((time.perf_counter() - t0) * 1e6)
        request_id = uuid.uuid4().hex
        VERIFY_LATENCY.labels(out.lane.value).observe(latency_us / 1e6)
        DECISIONS.labels(airline_id, out.lane.value, out.decision.value).inc()
        if out.degraded:
            DEGRADED.labels(airline_id).inc()

        self.events.emit({
            "ts": now_ms, "request_id": request_id, "airline_id": airline_id, "lane": out.lane.value,
            "decision": out.decision.value, "score": round(out.score, 2),
            "reason_codes": [r["signal"] for r in out.reasons], "tool_id": out.tool_id,
            "failure": out.failure, "attributable": out.attributable, "ip": req.client_ip, "dc": is_dc,
            "latency_us": latency_us,
            "origin": req.search.origin.upper() if req.search else None,
            "destination": req.search.destination.upper() if req.search else None,
            "date": req.search.date if req.search else None, "cabin": req.search.cabin if req.search else None,
            "rate_limited": out.decision is Decision.throttle and out.retry_after_s is not None,
            **ctx,
        })
        return VerifyResponse(
            request_id=request_id, decision=out.decision, lane=out.lane, score=round(out.score, 1),
            pillars=out.pillars, reasons=[Reason(**r) for r in pillars.tag(out.reasons)], tool_id=out.tool_id, retry_after_s=out.retry_after_s,
            policy_version=prec.version, degraded=out.degraded, latency_us=latency_us,
        )

    # --- authenticated lane -----------------------------------------------------

    async def _authenticated(self, req: VerifyRequest, headers: dict, airline_id: str, policy: AirlinePolicy,
                             now_ms: int, is_dc: bool, ctx: dict) -> Outcome:
        lane = Lane.authenticated
        now_s = now_ms // 1000
        if "signature-input" not in headers or "signature" not in headers:
            return _block(lane, "missing_signature")
        auth = headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return _block(lane, "missing_token")

        try:
            params = httpsig.parse_signature_input(headers["signature-input"])
            sig = httpsig.parse_signature(headers["signature"], params.label)
        except httpsig.SignatureError as e:
            return _block(lane, e.code, str(e), failure=e.code)
        tool = self.registry.tools_by_jkt.get(params.keyid)
        if tool is None:
            return _block(lane, "unknown_key", failure="unknown_key")
        ctx["claimed_tool_id"] = tool.tool_id
        if tool.status != "active":
            return _block(lane, "tool_revoked", tool_id=tool.tool_id, failure="tool_revoked")
        body = base64.b64decode(req.request.body_b64) if req.request.body_b64 else None
        try:
            httpsig.verify_request(tool.public_key, params, sig, req.request.method, req.request.url, headers,
                                   now=now_s, skew_s=self.s.clock_skew_s, max_age_s=self.s.max_signature_age_s,
                                   body=body)
        except httpsig.SignatureError as e:
            return _block(lane, e.code, str(e), tool_id=tool.tool_id, failure=e.code)

        # From here on the request is provably from the holder of the tool's key.
        def fail(code: str, msg: str | None = None) -> Outcome:
            return _block(lane, code, msg, tool_id=tool.tool_id, failure=code, attributable=code in ATTRIBUTABLE)

        try:
            at = self.registry.tokens.verify(auth[7:].strip(), airline_id, now_s)
        except TokenError as e:
            return fail(e.code, str(e))
        if at.jkt != params.keyid:
            return fail("key_mismatch")
        if at.tool_id != tool.tool_id:
            return fail("client_mismatch")
        ctx.update(grant_id=at.grant_id, member_ref=at.member_ref, jti=at.jti, iat=at.iat, exp=at.exp,
                   auth_time=at.auth_time, routes=sorted(at.routes) if at.routes else None)
        if not policy.authorized_agents_allowed:
            return _block(lane, "agents_not_permitted", tool_id=tool.tool_id, failure="agents_not_permitted")
        if at.routes is not None and (req.search is None or req.search.route not in at.routes):
            return fail("route_not_authorized")
        if is_dc and policy.vpn_tolerance is VpnTolerance.block:
            return _block(lane, "vpn_not_permitted", tool_id=tool.tool_id, failure="vpn_not_permitted")

        # Young grants run on a reduced quota until they've earned trust.
        factor = 1.0
        if at.auth_time is not None and now_s - at.auth_time < policy.min_grant_age_s:
            factor = policy.new_grant_rate_factor
        g_rate, g_cap = store.bucket_params(policy.max_searches_per_min_per_credential * factor,
                                            policy.burst_multiplier)
        t_rate, t_cap = store.bucket_params(policy.max_searches_per_min_per_tool, policy.burst_multiplier)
        ctx["effective_limit"] = policy.max_searches_per_min_per_credential * factor

        keys = [store.nonce_key(tool.tool_id, params.nonce), store.revoked_tool_key(tool.tool_id),
                store.revoked_grant_key(tool.tool_id, at.grant_id), store.grant_bucket_key(tool.tool_id, at.grant_id),
                store.tool_bucket_key(tool.tool_id, airline_id),
                store.grant_risk_key(tool.tool_id, airline_id, at.grant_id),
                store.tool_risk_key(tool.tool_id, airline_id)]
        args = [self.s.max_signature_age_s + 2 * self.s.clock_skew_s, now_ms, g_rate, g_cap, t_rate, t_cap,
                store.BUCKET_TTL_MS]
        try:
            res = await self._within_budget(self._auth_script(keys=keys, args=args))
        except (asyncio.TimeoutError, OSError, aioredis.RedisError):
            return self._degraded(lane, policy, tool.tool_id)
        status, retry_ms = res[0].decode(), res[1]

        if status == "replay":
            return fail("replay")
        if status in ("revoked_tool", "revoked_grant"):
            code = status.replace("revoked_", "") + "_revoked"
            return _block(lane, code, res[2].decode() if res[2] else None, tool_id=tool.tool_id, failure=code)
        g_score, g_reasons, t_score, t_reasons = res[2:6]

        sync: list[Contribution] = []
        if is_dc and policy.weights_authenticated.get("vpn", 0) > 0:
            w = policy.weights_authenticated["vpn"]
            sync.append(Contribution("vpn", 0.5, evidence(w, 0.5), "request came from a datacenter / VPN range",
                                     "This airline scores datacenter egress; prefer stable egress IPs."))
        # Grant behavior and tool-wide verification failures are independent evidence.
        prior = sum(evidence_from_score(float(s)) for s in (g_score, t_score) if s)
        result = combine(sync, prior)
        g_cached, t_cached = _cached_reasons(g_reasons), _cached_reasons(t_reasons)
        reasons = g_cached + t_cached + result.reasons()
        breakdown = pillars.breakdown(result.score, [pillars.from_cached(g_score, g_cached),
                                                     pillars.from_cached(t_score, t_cached),
                                                     (result.total_evidence, result.reasons())])
        decision = decide(result.score, lane, policy.thresholds)

        retry_after = None
        if status in ("rate_credential", "rate_tool"):
            retry_after = max(1, -(-int(retry_ms) // 1000))
            which = "credential" if status == "rate_credential" else "tool (all users at this airline)"
            limit = ctx["effective_limit"] if status == "rate_credential" else policy.max_searches_per_min_per_tool
            reasons.insert(0, {"signal": status, "detail": f"{which} rate limit of {limit:g}/min reached",
                               "advice": f"Retry after {retry_after}s; spread searches evenly."})
            if decision in (Decision.allow, Decision.flag):
                decision = Decision.throttle
        return Outcome(decision, lane, result.score, reasons, tool_id=tool.tool_id, retry_after_s=retry_after,
                       pillars=breakdown)

    # --- unauthenticated lane ----------------------------------------------------

    async def _unauthenticated(self, req: VerifyRequest, headers: dict, airline_id: str, policy: AirlinePolicy,
                               now_ms: int, is_dc: bool, ctx: dict) -> Outcome:
        lane = Lane.unauthenticated
        cs = req.client_signals
        device_ref = hashlib.sha256(f"{airline_id}:{cs.device_id}".encode()).hexdigest()[:24] if cs.device_id else None
        ctx["device_ref"] = device_ref
        ctx["ua"] = headers.get("user-agent", "")[:200]
        if is_dc and policy.vpn_tolerance is VpnTolerance.block:
            return _block(lane, "vpn_not_permitted", failure="vpn_not_permitted")

        # Request-local evidence needs no Redis, so it still applies when the risk store is unavailable.
        sync = score_unauthenticated(UnauthFeatures(
            automation=automation_strength(headers, cs.model_dump()),
            is_datacenter=is_dc, external_bot_score=cs.bot_score), policy)

        # With a first-party device id the per-client limit applies to the device, and the IP only gets a
        # ceiling (offices and carrier NAT put many people behind one address). Without one, the IP is the client.
        limit = policy.max_searches_per_min_per_ip_unauthenticated
        rate, cap = store.bucket_params(limit, policy.burst_multiplier)
        ip_rate, ip_cap = store.bucket_params(limit * (policy.max_devices_per_ip if device_ref else 1),
                                              policy.burst_multiplier)
        ip_bucket = store.ip_bucket_key(airline_id, req.client_ip)
        ip_risk = store.ip_risk_key(airline_id, req.client_ip)
        try:
            res = await self._within_budget(self._unauth_script(
                keys=[store.device_bucket_key(airline_id, device_ref) if device_ref else ip_bucket, ip_bucket,
                      ip_risk, store.device_risk_key(airline_id, device_ref) if device_ref else ip_risk],
                args=[now_ms, rate, cap, ip_rate, ip_cap, 1 if device_ref else 0, store.BUCKET_TTL_MS]))
        except (asyncio.TimeoutError, OSError, aioredis.RedisError):
            out = self._degraded(lane, policy, None)
            if decide(sync.score, lane, policy.thresholds) in (Decision.block, Decision.throttle):
                out.decision, out.score = Decision.block, sync.score
                out.reasons = sync.reasons() + out.reasons
                out.pillars = pillars.breakdown(sync.score, [(sync.total_evidence, sync.reasons())])
            return out
        status, retry_ms, ip_score, ip_reasons, dev_score, dev_reasons = res
        status = status.decode()

        # Device evidence is specific to this client; IP evidence may belong to the other people behind a
        # shared address, so it counts for less when we can tell clients apart.
        ip_e = evidence_from_score(float(ip_score)) if ip_score else 0.0
        dev_e = evidence_from_score(float(dev_score)) if dev_score else 0.0
        ip_w = SHARED_IP_DISCOUNT if device_ref else 1.0
        prior = dev_e + ip_w * ip_e
        prior_reasons = dev_reasons if dev_e >= ip_e else ip_reasons
        result = combine(sync.contributions, prior)
        reasons = _cached_reasons(prior_reasons) + result.reasons()
        breakdown = pillars.breakdown(result.score, [(dev_e, _cached_reasons(dev_reasons)),
                                                     (ip_w * ip_e, _cached_reasons(ip_reasons)),
                                                     (result.total_evidence, result.reasons())])
        decision = decide(result.score, lane, policy.thresholds)
        if is_dc and policy.vpn_tolerance is VpnTolerance.authenticated_only and decision is Decision.allow:
            # Plenty of humans use consumer VPNs: challenge rather than block.
            decision = Decision.challenge
            reasons.append({"signal": "vpn", "detail": "datacenter / VPN address without agent credentials",
                            "advice": ""})
        if policy.unauthenticated_mode is UnauthenticatedMode.challenge and decision is Decision.allow:
            decision = Decision.challenge
        retry_after = None
        if status in ("rate_client", "rate_ip"):
            retry_after = max(1, -(-int(retry_ms) // 1000))
            reasons.insert(0, {"signal": status, "advice": "",
                               "detail": f"{'IP' if status == 'rate_ip' else 'per-client'} rate limit reached"})
            if decision in (Decision.allow, Decision.challenge):
                decision = Decision.throttle
        return Outcome(decision, lane, result.score, reasons, retry_after_s=retry_after, pillars=breakdown)

    async def _within_budget(self, coro):
        """Await a Redis call for at most redis_timeout_ms without cancelling it.

        Cancelling a command mid-flight forces redis-py to drop the connection; under load that
        turns into reconnect storms that make every later call slower. Past the deadline we
        decide without Redis and let the call finish in the background, returning its connection
        to the pool intact.
        """
        task = asyncio.ensure_future(coro)
        done, _ = await asyncio.wait((task,), timeout=self.s.redis_timeout_ms / 1000)
        if not done:
            LATE_REDIS.inc()
            task.add_done_callback(lambda t: t.cancelled() or t.exception())  # consume, don't log as unhandled
            raise asyncio.TimeoutError
        return task.result()

    def _degraded(self, lane: Lane, policy: AirlinePolicy, tool_id: str | None) -> Outcome:
        decision = Decision.allow if policy.fail_mode is FailMode.open else Decision.block
        return Outcome(decision, lane, 0.0, [{"signal": "degraded", "advice": "",
                                              "detail": f"risk store unavailable; airline fail mode is "
                                                        f"{policy.fail_mode.value}"}],
                       tool_id=tool_id, degraded=True)
