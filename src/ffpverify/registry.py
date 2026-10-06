"""In-memory view of airlines, policies and tool keys, kept fresh via Redis pub/sub.

The hot path never touches Postgres: everything it needs is here. Changes are written
to Postgres first, then announced on CONFIG_CHANNEL so every replica reloads the one
record that changed. A periodic full reload covers any missed messages.
"""

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass

import asyncpg
import httpx
import redis.asyncio as aioredis
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import load_public_jwk
from .policy import AirlinePolicy
from .store import CONFIG_CHANNEL
from .tokens import TokenVerifier

log = logging.getLogger(__name__)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


@dataclass(frozen=True)
class ToolRecord:
    tool_id: str
    jkt: str
    public_key: Ed25519PublicKey
    status: str


@dataclass(frozen=True)
class PolicyRecord:
    version: int
    policy: AirlinePolicy


class Registry:
    def __init__(self, pool: asyncpg.Pool, redis: aioredis.Redis, tokens: TokenVerifier):
        self.pool = pool
        self.redis = redis
        self.tokens = tokens
        self.airline_by_key_hash: dict[str, str] = {}
        self.policies: dict[str, PolicyRecord] = {}
        self.tools_by_jkt: dict[str, ToolRecord] = {}
        self._tasks: list[asyncio.Task] = []

    # --- loading ---------------------------------------------------------------

    async def load_all(self) -> None:
        async with self.pool.acquire() as conn:
            airlines = await conn.fetch("SELECT airline_id FROM airlines")
            tools = await conn.fetch("SELECT tool_id FROM authorized_tools")
        for row in airlines:
            await self.reload_airline(row["airline_id"])
        for row in tools:
            await self.reload_tool(row["tool_id"])

    async def reload_airline(self, airline_id: str) -> None:
        async with self.pool.acquire() as conn:
            a = await conn.fetchrow("SELECT * FROM airlines WHERE airline_id = $1", airline_id)
            p = await conn.fetchrow("SELECT version, policy FROM airline_policies WHERE airline_id = $1", airline_id)
        for h, aid in list(self.airline_by_key_hash.items()):
            if aid == airline_id:
                del self.airline_by_key_hash[h]
        if a is None:
            self.policies.pop(airline_id, None)
            self.tokens.remove_airline(airline_id)
            return
        self.airline_by_key_hash[a["api_key_hash"]] = airline_id
        self.policies[airline_id] = (PolicyRecord(p["version"], AirlinePolicy.model_validate(p["policy"]))
                                     if p else PolicyRecord(0, AirlinePolicy()))
        jwks = a["jwks"]
        if jwks is None and a["jwks_uri"]:
            async with httpx.AsyncClient(timeout=5) as client:
                jwks = (await client.get(a["jwks_uri"])).json()
        try:
            self.tokens.set_airline_keys(airline_id, a["issuer"], jwks or {"keys": []})
        except Exception:
            log.exception("airline %s has an unusable JWKS", airline_id)

    async def reload_tool(self, tool_id: str) -> None:
        async with self.pool.acquire() as conn:
            t = await conn.fetchrow("SELECT tool_id, jkt, public_jwk, status FROM authorized_tools WHERE tool_id = $1",
                                    tool_id)
        for jkt, rec in list(self.tools_by_jkt.items()):
            if rec.tool_id == tool_id:
                del self.tools_by_jkt[jkt]
        if t is not None:
            self.tools_by_jkt[t["jkt"]] = ToolRecord(t["tool_id"], t["jkt"], load_public_jwk(t["public_jwk"]),
                                                     t["status"])

    # --- change propagation ------------------------------------------------------

    async def announce(self, kind: str, ident: str) -> None:
        await self.redis.publish(CONFIG_CHANNEL, json.dumps({"kind": kind, "id": ident}))

    async def _listen(self) -> None:
        while True:
            try:
                pubsub = self.redis.pubsub()
                await pubsub.subscribe(CONFIG_CHANNEL)
                async for msg in pubsub.listen():
                    if msg["type"] != "message":
                        continue
                    data = json.loads(msg["data"])
                    if data["kind"] == "airline":
                        await self.reload_airline(data["id"])
                    elif data["kind"] == "tool":
                        await self.reload_tool(data["id"])
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("config listener failed; resubscribing")
                await asyncio.sleep(1)

    async def _periodic(self, interval_s: float) -> None:
        while True:
            await asyncio.sleep(interval_s)
            try:
                await self.load_all()
            except Exception:
                log.exception("periodic registry reload failed")

    def start(self, full_reload_interval_s: float = 60) -> None:
        self._tasks = [asyncio.create_task(self._listen()), asyncio.create_task(self._periodic(full_reload_interval_s))]

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
