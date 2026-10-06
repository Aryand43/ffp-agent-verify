"""ffp-agent-verify HTTP API."""

import base64
import hmac
import logging
import secrets
import time
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path

import orjson
import redis.asyncio as aioredis
from cryptography.exceptions import InvalidSignature
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import ValidationError

from .. import inventory, store
from ..config import Settings, get_settings
from ..crypto import jwk_thumbprint, load_public_jwk
from ..db import create_pool, migrate
from ..events import EventBuffer
from ..models import (AirlineCreate, AirlineCreated, FeedbackCreate, RevokeRequest, ToolRegister, ToolRegistered,
                      VerifyRequest, VerifyResponse)
from ..policy import AirlinePolicy
from ..registry import Registry, hash_secret
from ..tokens import TokenVerifier
from ..verify import Verifier

log = logging.getLogger(__name__)
STATIC = Path(__file__).parent / "static"

TAGS = [
    {"name": "verification", "description": "Hot path, called by airlines for every award search."},
    {"name": "airlines", "description": "Airline onboarding and risk policy."},
    {"name": "tools", "description": "FFP monitoring tool registration, keys and analytics."},
    {"name": "inventory", "description": "Redemption (award) seat inventory per flight, date and award class."},
    {"name": "feedback", "description": "Ground-truth labels from airlines."},
]


def create_app(settings: Settings | None = None) -> FastAPI:
    s = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        pool = await create_pool(s.database_url)
        await migrate(pool)
        redis = aioredis.from_url(s.redis_url, max_connections=200, socket_keepalive=True)
        registry = Registry(pool, redis, TokenVerifier(s.token_audience, s.clock_skew_s, s.max_token_lifetime_s))
        await registry.load_all()
        await _sync_revocations(pool, redis)
        registry.start()
        events = EventBuffer(redis, s.events_stream, s.events_stream_maxlen)
        events.start()
        app.state.pool, app.state.redis, app.state.registry = pool, redis, registry
        app.state.verifier = Verifier(s, registry, redis, events)
        app.state.events = events
        yield
        await events.stop()
        await registry.stop()
        await redis.aclose()
        await pool.close()

    app = FastAPI(title="ffp-agent-verify", version="0.1.0", lifespan=lifespan, openapi_tags=TAGS,
                  description="Verify and risk-score automated frequent-flyer award searches. "
                              "See docs/ for integration guides.")

    # --- auth dependencies ----------------------------------------------------------

    def admin(x_admin_key: str = Header(...)) -> None:
        if not hmac.compare_digest(x_admin_key, s.admin_key):
            raise HTTPException(401, "bad admin key")

    def airline(request: Request, x_api_key: str = Header(...)) -> str:
        airline_id = request.app.state.registry.airline_by_key_hash.get(hash_secret(x_api_key))
        if airline_id is None:
            raise HTTPException(401, "bad airline API key")
        return airline_id

    def airline_or_admin(airline_id: str, request: Request, x_api_key: str | None = Header(None),
                         x_admin_key: str | None = Header(None)) -> str:
        if x_admin_key and hmac.compare_digest(x_admin_key, s.admin_key):
            return "admin"
        if x_api_key and request.app.state.registry.airline_by_key_hash.get(hash_secret(x_api_key)) == airline_id:
            return f"airline:{airline_id}"
        raise HTTPException(401, "airline API key for this airline, or admin key, required")

    async def tool_or_admin(tool_id: str, request: Request, x_tool_token: str | None = Header(None),
                            x_admin_key: str | None = Header(None)) -> str:
        if x_admin_key and hmac.compare_digest(x_admin_key, s.admin_key):
            return "admin"
        if x_tool_token:
            h = await request.app.state.pool.fetchval(
                "SELECT management_token_hash FROM authorized_tools WHERE tool_id = $1", tool_id)
            if h and hmac.compare_digest(h, hash_secret(x_tool_token)):
                return f"tool:{tool_id}"
        raise HTTPException(401, "tool management token or admin key required")

    # --- verification ---------------------------------------------------------------------

    @app.post("/v1/search/verify", response_model=VerifyResponse, tags=["verification"])
    async def verify(body: VerifyRequest, request: Request, airline_id: str = Depends(airline)):
        """Verify one incoming award search. Returns allow / flag / challenge / throttle / block.

        Act on `decision`; show `reasons` to the tool (they're written for tool developers).
        """
        return await request.app.state.verifier.verify(body, airline_id)

    # --- airlines ---------------------------------------------------------------------------

    @app.post("/v1/airlines", response_model=AirlineCreated, tags=["airlines"], dependencies=[Depends(admin)])
    async def create_airline(body: AirlineCreate, request: Request):
        if not body.jwks and not body.jwks_uri:
            raise HTTPException(422, "jwks or jwks_uri required")
        api_key = "ffpv_ak_" + secrets.token_urlsafe(24)
        pool = request.app.state.pool
        async with pool.acquire() as conn, conn.transaction():
            exists = await conn.fetchval("SELECT 1 FROM airlines WHERE airline_id = $1", body.airline_id)
            if exists:
                raise HTTPException(409, "airline exists")
            await conn.execute("INSERT INTO airlines (airline_id, name, issuer, jwks, jwks_uri, api_key_hash) "
                               "VALUES ($1, $2, $3, $4, $5, $6)", body.airline_id, body.name, str(body.issuer),
                               body.jwks, body.jwks_uri, hash_secret(api_key))
            policy = AirlinePolicy().model_dump(mode="json")
            await conn.execute("INSERT INTO airline_policies (airline_id, version, policy, updated_by) "
                               "VALUES ($1, 1, $2, 'admin')", body.airline_id, policy)
            await conn.execute("INSERT INTO airline_policy_versions (airline_id, version, policy, updated_by) "
                               "VALUES ($1, 1, $2, 'admin')", body.airline_id, policy)
        await request.app.state.registry.reload_airline(body.airline_id)
        await request.app.state.registry.announce("airline", body.airline_id)
        return AirlineCreated(airline_id=body.airline_id, api_key=api_key)

    @app.put("/v1/airlines/{airline_id}/jwks", tags=["airlines"])
    async def rotate_airline_keys(airline_id: str, body: dict, request: Request,
                                  who: str = Depends(airline_or_admin)):
        """Replace the airline authorization server's signing keys (JWKS)."""
        n = await request.app.state.pool.execute("UPDATE airlines SET jwks = $2 WHERE airline_id = $1",
                                                 airline_id, body)
        if n.endswith(" 0"):
            raise HTTPException(404, "unknown airline")
        await request.app.state.registry.reload_airline(airline_id)
        await request.app.state.registry.announce("airline", airline_id)
        return {"ok": True}

    @app.get("/v1/airlines/{airline_id}/policy", tags=["airlines"])
    async def get_policy(airline_id: str, request: Request, who: str = Depends(airline_or_admin)):
        rec = request.app.state.registry.policies.get(airline_id)
        if rec is None:
            raise HTTPException(404, "unknown airline")
        return {"airline_id": airline_id, "version": rec.version, "policy": rec.policy.model_dump(mode="json")}

    async def _save_policy(request: Request, airline_id: str, policy: AirlinePolicy, who: str) -> dict:
        pool = request.app.state.pool
        data = policy.model_dump(mode="json")
        async with pool.acquire() as conn, conn.transaction():
            version = await conn.fetchval(
                "UPDATE airline_policies SET version = version + 1, policy = $2, updated_at = now(), updated_by = $3 "
                "WHERE airline_id = $1 RETURNING version", airline_id, data, who)
            if version is None:
                raise HTTPException(404, "unknown airline")
            await conn.execute("INSERT INTO airline_policy_versions (airline_id, version, policy, updated_by) "
                               "VALUES ($1, $2, $3, $4)", airline_id, version, data, who)
        await request.app.state.registry.reload_airline(airline_id)
        await request.app.state.registry.announce("airline", airline_id)
        return {"airline_id": airline_id, "version": version, "policy": data}

    @app.put("/v1/airlines/{airline_id}/policy", tags=["airlines"])
    async def put_policy(airline_id: str, body: AirlinePolicy, request: Request,
                         who: str = Depends(airline_or_admin)):
        """Replace the airline's policy. Takes effect on every replica within ~1s, no redeploy."""
        return await _save_policy(request, airline_id, body, who)

    @app.patch("/v1/airlines/{airline_id}/policy", tags=["airlines"])
    async def patch_policy(airline_id: str, body: dict, request: Request, who: str = Depends(airline_or_admin)):
        """Merge a partial policy (e.g. `{"max_searches_per_min_per_credential": 20}`) into the current one."""
        rec = request.app.state.registry.policies.get(airline_id)
        if rec is None:
            raise HTTPException(404, "unknown airline")
        merged = rec.policy.model_dump(mode="json")
        for k, v in body.items():
            merged[k] = {**merged[k], **v} if isinstance(v, dict) and isinstance(merged.get(k), dict) else v
        try:
            policy = AirlinePolicy.model_validate(merged)
        except ValidationError as e:
            raise HTTPException(422, orjson.loads(e.json())) from None
        return await _save_policy(request, airline_id, policy, who)

    @app.get("/v1/airlines/{airline_id}/stats", tags=["airlines"])
    async def airline_stats(airline_id: str, request: Request, hours: int = 24,
                            who: str = Depends(airline_or_admin)):
        """Decision mix, top reasons, latency, riskiest tools and recent risk events for this airline."""
        pool = request.app.state.pool
        since = "now() - make_interval(hours => $2)"
        decisions = await pool.fetch(
            f"SELECT lane, decision, count(*) n FROM search_requests WHERE airline_id = $1 AND ts > {since} "
            f"GROUP BY 1, 2 ORDER BY 1, 2", airline_id, hours)
        latency = await pool.fetchrow(
            f"SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY verify_latency_us) p50, "
            f"percentile_cont(0.99) WITHIN GROUP (ORDER BY verify_latency_us) p99 "
            f"FROM search_requests WHERE airline_id = $1 AND ts > {since}", airline_id, hours)
        reasons = await pool.fetch(
            f"SELECT r, count(*) n FROM search_requests, unnest(reason_codes) r WHERE airline_id = $1 "
            f"AND ts > {since} GROUP BY r ORDER BY n DESC LIMIT 10", airline_id, hours)
        tools = await pool.fetch(
            "SELECT t.tool_id, t.name, t.status, max(g.risk_score) risk, count(*) grants, "
            "count(*) FILTER (WHERE g.status = 'revoked') revoked FROM grants g JOIN authorized_tools t "
            "USING (tool_id) WHERE g.airline_id = $1 GROUP BY 1, 2, 3 ORDER BY risk DESC LIMIT 15", airline_id)
        events = await pool.fetch(
            "SELECT ts, lane, subject_type, subject_id, risk_score, action_taken, flags FROM risk_events "
            "WHERE airline_id = $1 ORDER BY ts DESC LIMIT 25", airline_id)
        return {"airline_id": airline_id, "window_hours": hours,
                "decisions": [dict(r) for r in decisions],
                "latency_us": dict(latency) if latency else None,
                "top_reasons": [dict(r) for r in reasons],
                "tools": [dict(r) for r in tools],
                "recent_events": [dict(r) for r in events]}

    @app.post("/v1/airlines/{airline_id}/grants/{grant_id}/revoke", tags=["airlines"])
    async def revoke_grant(airline_id: str, grant_id: str, body: RevokeRequest, request: Request,
                           who: str = Depends(airline_or_admin)):
        """Revoke one member's authorization of a tool at this airline (credential revocation)."""
        tool_id = await request.app.state.pool.fetchval(
            "UPDATE grants SET status = 'revoked', status_reason = $3 WHERE grant_id = $1 AND airline_id = $2 "
            "RETURNING tool_id", grant_id, airline_id, body.reason)
        if tool_id is None:
            raise HTTPException(404, "unknown grant")
        await request.app.state.redis.set(store.revoked_grant_key(tool_id, grant_id), body.reason)
        return {"ok": True}

    # --- tools ---------------------------------------------------------------------------------

    @app.post("/v1/tools/register", response_model=ToolRegistered, tags=["tools"])
    async def register_tool(body: ToolRegister, request: Request):
        """Register a tool's Ed25519 public key. `proof` shows the caller holds the private key."""
        try:
            pub = load_public_jwk(body.public_jwk)
            jkt = jwk_thumbprint(body.public_jwk)
        except (ValueError, KeyError) as e:
            raise HTTPException(422, f"bad public_jwk: {e}") from None
        if abs(time.time() - body.proof_ts) > 300:
            raise HTTPException(422, "proof_ts must be within 5 minutes of now")
        try:
            pub.verify(base64.b64decode(body.proof), f"ffpv-register:{jkt}:{body.proof_ts}".encode())
        except (InvalidSignature, ValueError):
            raise HTTPException(422, "proof signature invalid") from None
        tool_id = "tool_" + secrets.token_urlsafe(9)
        token = "ffpv_tt_" + secrets.token_urlsafe(24)
        jwk = {k: body.public_jwk[k] for k in ("kty", "crv", "x")}
        try:
            await request.app.state.pool.execute(
                "INSERT INTO authorized_tools (tool_id, name, developer_contact, public_jwk, jkt, redirect_uris, "
                "management_token_hash) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                tool_id, body.name, body.developer_contact, jwk, jkt, body.redirect_uris, hash_secret(token))
        except Exception as e:
            if "unique" in str(e).lower():
                raise HTTPException(409, "this public key is already registered") from None
            raise
        await request.app.state.registry.reload_tool(tool_id)
        await request.app.state.registry.announce("tool", tool_id)
        return ToolRegistered(tool_id=tool_id, jkt=jkt, management_token=token)

    @app.get("/v1/tools/{tool_id}/jwks", tags=["tools"])
    async def tool_jwks(tool_id: str, request: Request):
        """Public: the tool's current key(s). Airline authorization servers use this for private_key_jwt
        client authentication and to check the `dpop_jkt` they bind tokens to."""
        row = await request.app.state.pool.fetchrow(
            "SELECT public_jwk, jkt, status, redirect_uris, name FROM authorized_tools WHERE tool_id = $1", tool_id)
        if row is None:
            raise HTTPException(404, "unknown tool")
        keys = [{**row["public_jwk"], "kid": row["jkt"], "use": "sig", "alg": "EdDSA"}] \
            if row["status"] == "active" else []
        return {"keys": keys, "status": row["status"], "name": row["name"], "redirect_uris": row["redirect_uris"]}

    @app.post("/v1/tools/{tool_id}/revoke", tags=["tools"])
    async def revoke_tool(tool_id: str, body: RevokeRequest, request: Request, who: str = Depends(tool_or_admin)):
        """Revoke a tool's key everywhere (key compromise, or confirmed abuse)."""
        await request.app.state.pool.execute(
            "UPDATE authorized_tools SET status = 'revoked', status_reason = $2 WHERE tool_id = $1", tool_id,
            f"{who}: {body.reason}")
        await request.app.state.redis.set(store.revoked_tool_key(tool_id), body.reason)
        await request.app.state.registry.reload_tool(tool_id)
        await request.app.state.registry.announce("tool", tool_id)
        return {"ok": True}

    @app.get("/v1/tools/{tool_id}/analytics", tags=["tools"])
    async def tool_analytics(tool_id: str, request: Request, hours: int = 24, who: str = Depends(tool_or_admin)):
        """The tool's risk profile: decisions, reasons, riskiest grants and the quotas it must respect."""
        pool, redis = request.app.state.pool, request.app.state.redis
        tool = await pool.fetchrow("SELECT tool_id, name, status, status_reason, risk_score, created_at, last_seen "
                                   "FROM authorized_tools WHERE tool_id = $1", tool_id)
        if tool is None:
            raise HTTPException(404, "unknown tool")
        since = "now() - make_interval(hours => $2)"
        decisions = await pool.fetch(
            f"SELECT airline_id, decision, count(*) n, percentile_cont(0.99) WITHIN GROUP "
            f"(ORDER BY verify_latency_us) p99_us FROM search_requests WHERE tool_id = $1 AND ts > {since} "
            f"GROUP BY 1, 2 ORDER BY 1, 2", tool_id, hours)
        reasons = await pool.fetch(
            f"SELECT r, count(*) n FROM search_requests, unnest(reason_codes) r WHERE tool_id = $1 AND ts > {since} "
            f"GROUP BY r ORDER BY n DESC LIMIT 10", tool_id, hours)
        grants = await pool.fetch(
            "SELECT grant_id, airline_id, status, status_reason, risk_score, last_seen FROM grants WHERE tool_id = $1 "
            "ORDER BY risk_score DESC LIMIT 10", tool_id)
        live = []
        for g in grants[:5]:
            raw = await redis.hget(store.grant_risk_key(tool_id, g["airline_id"], g["grant_id"]), "r")
            live.append({"grant_id": g["grant_id"], "airline_id": g["airline_id"],
                         "reasons": orjson.loads(raw) if raw else []})
        policies = request.app.state.registry.policies
        quotas = {a: {"max_searches_per_min_per_credential": p.policy.max_searches_per_min_per_credential,
                      "max_searches_per_min_per_tool": p.policy.max_searches_per_min_per_tool,
                      "min_ip_rotation_interval_s": p.policy.min_ip_rotation_interval_s,
                      "min_grant_age_s": p.policy.min_grant_age_s,
                      "vpn_tolerance": p.policy.vpn_tolerance.value,
                      "authorized_agents_allowed": p.policy.authorized_agents_allowed}
                  for a, p in policies.items()}
        grant_counts = await pool.fetch("SELECT status, count(*) n FROM grants WHERE tool_id = $1 GROUP BY 1", tool_id)
        return {
            "tool": dict(tool), "window_hours": hours,
            "decisions": [dict(r) for r in decisions],
            "top_reasons": [dict(r) for r in reasons],
            "grants": {r["status"]: r["n"] for r in grant_counts},
            "riskiest_grants": [dict(g) for g in grants],
            "live_reasons": live,
            "airline_quotas": quotas,
        }

    # --- inventory ------------------------------------------------------------------------------

    @app.put("/v1/airlines/{airline_id}/inventory", response_model=inventory.InventoryIngested, tags=["inventory"])
    async def push_inventory(airline_id: str, body: inventory.InventoryUpload, request: Request,
                             who: str = Depends(airline_or_admin)):
        """The airline's own redemption inventory feed: seats open vs. the cap, per flight, date and award class.

        Upserts by (operating carrier, flight, date, award class). Include partner / alliance space with
        `operating_carrier`. Older snapshots never overwrite newer ones.
        """
        if airline_id not in request.app.state.registry.policies:
            raise HTTPException(404, "unknown airline")
        return await inventory.ingest(request.app.state.pool, airline_id, body, "airline_feed")

    @app.post("/v1/tools/{tool_id}/inventory/{airline_id}", response_model=inventory.InventoryIngested,
              tags=["inventory"])
    async def report_inventory(tool_id: str, airline_id: str, body: inventory.InventoryUpload, request: Request,
                               who: str = Depends(tool_or_admin)):
        """An authorized tool reports the award availability its searches returned at `airline_id`.

        Only tools with an active member authorization at that airline (one that has made a verified search
        there) may report. `seats_total` is optional; the last
        known cap is kept when it's missing.
        """
        if airline_id not in request.app.state.registry.policies:
            raise HTTPException(404, "unknown airline")
        if who.startswith("tool:") and not await request.app.state.pool.fetchval(
                "SELECT 1 FROM grants WHERE tool_id = $1 AND airline_id = $2 AND status = 'active' LIMIT 1",
                tool_id, airline_id):
            raise HTTPException(403, "tool has no active member authorization at this airline")
        return await inventory.ingest(request.app.state.pool, airline_id, body, f"tool:{tool_id}")

    @app.get("/v1/airlines/{airline_id}/inventory", tags=["inventory"])
    async def get_inventory(airline_id: str, request: Request, origin: str | None = None,
                            destination: str | None = None, date_from: date | None = None,
                            date_to: date | None = None, cabin: str | None = None, award_class: str | None = None,
                            operating_carrier: str | None = None, partner_only: bool = False,
                            available_only: bool = False, limit: int = 500, who: str = Depends(airline_or_admin)):
        """The redemption catalog for this program: departure, destination, date, cabin, award class and
        seats available vs. total, including partner space. `summary` totals seats per cabin and class."""
        return await inventory.query(request.app.state.pool, airline_id, origin=origin, destination=destination,
                                     date_from=date_from, date_to=date_to, cabin=cabin, award_class=award_class,
                                     operating_carrier=operating_carrier, partner_only=partner_only,
                                     available_only=available_only, limit=max(1, min(limit, 5000)))

    # --- feedback -------------------------------------------------------------------------------

    @app.post("/v1/feedback", tags=["feedback"], status_code=201)
    async def feedback(body: FeedbackCreate, request: Request, airline_id: str = Depends(airline)):
        """Label a decision (false positive / negative, confirmed abuse / legitimate) for tuning."""
        if not body.request_id and not body.tool_id:
            raise HTTPException(422, "request_id or tool_id required")
        fid = await request.app.state.pool.fetchval(
            "INSERT INTO feedback (airline_id, request_id, tool_id, label, notes) VALUES ($1, $2, $3, $4, $5) "
            "RETURNING feedback_id", airline_id, body.request_id, body.tool_id, body.label.value, body.notes)
        return {"feedback_id": fid}

    # --- ops ---------------------------------------------------------------------------------------

    @app.get("/", include_in_schema=False)
    async def root():
        return RedirectResponse("/ui")

    @app.get("/ui", include_in_schema=False)
    async def ui():
        return FileResponse(STATIC / "index.html")

    @app.get("/healthz", include_in_schema=False)
    async def healthz(request: Request):
        await request.app.state.redis.ping()
        return {"ok": True, "events_dropped": request.app.state.events.dropped}

    @app.get("/metrics", include_in_schema=False)
    async def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


async def _sync_revocations(pool, redis) -> None:
    """Postgres is the source of truth for revocations; re-assert them in Redis on startup."""
    tools = await pool.fetch("SELECT tool_id, status_reason FROM authorized_tools WHERE status <> 'active'")
    grants = await pool.fetch("SELECT tool_id, grant_id, status_reason FROM grants WHERE status = 'revoked'")
    if not tools and not grants:
        return
    pipe = redis.pipeline(transaction=False)
    for t in tools:
        pipe.set(store.revoked_tool_key(t["tool_id"]), t["status_reason"] or "revoked")
    for g in grants:
        pipe.set(store.revoked_grant_key(g["tool_id"], g["grant_id"]), g["status_reason"] or "revoked")
    await pipe.execute()


app = create_app()
