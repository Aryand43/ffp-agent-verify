"""In-process test environment: verify service + one reference AS per airline + risk worker.

Everything talks over real HTTP semantics (httpx -> ASGI) except two shortcuts that let
hours of traffic run in seconds: the verifier is called with an explicit `now_ms` from
a simulated clock, and events go straight from the verifier's buffer to the worker.
"""

import contextlib
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

import asyncpg
import httpx

from ffpverify.api.app import create_app
from ffpverify.config import Settings
from ffpverify.crypto import generate_private_key, jwk_thumbprint, public_jwk
from ffpverify.models import ClientSignals, ForwardedRequest, SearchInfo, VerifyRequest, VerifyResponse
from ffpverify.reference_as.app import create_as_app
from ffpverify.risk.worker import RiskWorker
from ffpverify.sdk.tool import Tokens, ToolClient

ADMIN_KEY = "test-admin-key"
VERIFY_HOST = "verify.test"
CHROME_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/129.0.0.0 Safari/537.36",
    "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-CA,en;q=0.9",
    "Sec-CH-UA": '"Chromium";v="129", "Google Chrome";v="129"',
}


class SimClock:
    def __init__(self, start: float | None = None):
        self.now = start if start is not None else time.time()

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    @property
    def ms(self) -> int:
        return int(self.now * 1000)


class HostRouter(httpx.AsyncBaseTransport):
    """Route requests to in-process ASGI apps by hostname."""

    def __init__(self):
        self.routes: dict[str, httpx.ASGITransport] = {}

    def mount(self, host: str, app) -> None:
        self.routes[host] = httpx.ASGITransport(app=app)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        transport = self.routes.get(request.url.host)
        if transport is None:
            raise httpx.ConnectError(f"no app mounted for {request.url.host}")
        return await transport.handle_async_request(request)


@dataclass
class AirlineEnv:
    code: str
    api_key: str
    issuer: str
    as_key: object
    as_app: object


@dataclass
class ToolEnv:
    client: ToolClient
    name: str
    management_token: str
    redirect_uri: str
    grants: dict = field(default_factory=dict)  # (airline, member) -> Tokens


@dataclass
class Env:
    settings: Settings
    app: object
    http: httpx.AsyncClient
    clock: SimClock
    airlines: dict[str, AirlineEnv]
    worker: RiskWorker

    @property
    def verify_url(self) -> str:
        return f"http://{VERIFY_HOST}"

    @property
    def state(self):
        return self.app.state

    async def register_tool(self, name: str) -> ToolEnv:
        key = generate_private_key()
        redirect = f"https://{name.lower()}.example/callback"
        reg = await ToolClient.register(self.http, self.verify_url, name, f"ops@{name.lower()}.example", [redirect],
                                        key)
        return ToolEnv(ToolClient(reg["tool_id"], key, self.http, clock=self.clock), name, reg["management_token"],
                       redirect)

    async def authorize(self, tool: ToolEnv, airline: str, member_id: str,
                        routes: list[str] | None = None) -> Tokens:
        """Run the full member-consent OAuth flow against the airline's reference AS."""
        a = self.airlines[airline]
        url, state, verifier = tool.client.authorization_url(a.issuer, tool.redirect_uri, routes)
        page = await self.http.get(url)
        page.raise_for_status()
        form = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        form.update(member_id=member_id, pin="4321", decision="approve", ffp_routes=form.get("ffp_routes", ""))
        form.pop("response_type", None)
        r = await self.http.post(f"{a.issuer}/oauth/authorize", data=form)
        assert r.status_code == 302, r.text
        q = parse_qs(urlsplit(r.headers["location"]).query)
        assert q["state"][0] == state
        tokens = await tool.client.exchange_code(a.issuer, q["code"][0], verifier, tool.redirect_uri)
        tool.grants[(airline, member_id)] = tokens
        return tokens

    async def fresh_tokens(self, tool: ToolEnv, airline: str, member_id: str) -> Tokens:
        tokens = tool.grants[(airline, member_id)]
        if tokens.needs_refresh(self.clock()):
            tokens = await tool.client.refresh(self.airlines[airline].issuer, tokens.refresh_token)
            tool.grants[(airline, member_id)] = tokens
        return tokens

    def tool_request(self, tool: ToolEnv, tokens: Tokens, airline: str, origin: str, dest: str, ip: str,
                     date: str = "2026-12-01", cabin: str = "business") -> VerifyRequest:
        url = f"https://api.{airline.lower()}.example/award/search?from={origin}&to={dest}&date={date}&cabin={cabin}"
        headers = tool.client.sign("GET", url, {"Accept": "application/json",
                                                "User-Agent": f"{tool.name}/1.4 (+https://{tool.name.lower()}.example)"},
                                   tokens.access_token, now=int(self.clock()))
        return VerifyRequest(request=ForwardedRequest(method="GET", url=url, headers=headers), client_ip=ip,
                             search=SearchInfo(origin=origin, destination=dest, date=date, cabin=cabin))

    def browser_request(self, airline: str, origin: str, dest: str, ip: str, headers: dict | None = None,
                        device_id: str | None = None, **signals) -> VerifyRequest:
        url = f"https://www.{airline.lower()}.example/award/search?from={origin}&to={dest}"
        return VerifyRequest(request=ForwardedRequest(method="GET", url=url,
                                                      headers=CHROME_HEADERS if headers is None else headers),
                             client_ip=ip, search=SearchInfo(origin=origin, destination=dest),
                             client_signals=ClientSignals(device_id=device_id, **signals))

    async def verify(self, req: VerifyRequest, airline: str) -> VerifyResponse:
        return await self.state.verifier.verify(req, airline, now_ms=self.clock.ms)

    async def verify_http(self, req: VerifyRequest, airline: str) -> httpx.Response:
        return await self.http.post(f"{self.verify_url}/v1/search/verify", json=req.model_dump(mode="json"),
                                    headers={"X-Api-Key": self.airlines[airline].api_key})

    async def tick(self) -> dict:
        """Run the risk worker over everything verified since the last tick."""
        return await self.worker.process_batch(self.state.events.drain())

    async def patch_policy(self, airline: str, patch: dict) -> dict:
        r = await self.http.patch(f"{self.verify_url}/v1/airlines/{airline}/policy", json=patch,
                                  headers={"X-Api-Key": self.airlines[airline].api_key})
        r.raise_for_status()
        return r.json()


def test_settings(db: str = "ffpv_test", redis_db: int = 15) -> Settings:
    return Settings(database_url=f"postgresql://ffpv:ffpv@localhost:5432/{db}",
                    redis_url=f"redis://localhost:6379/{redis_db}", admin_key=ADMIN_KEY, env="test")


async def reset_stores(settings: Settings) -> None:
    db = settings.database_url.rsplit("/", 1)[1]
    admin = await asyncpg.connect(settings.database_url.rsplit("/", 1)[0] + "/ffpv")
    try:
        if not await admin.fetchval("SELECT 1 FROM pg_database WHERE datname = $1", db):
            await admin.execute(f'CREATE DATABASE "{db}"')
    finally:
        await admin.close()
    conn = await asyncpg.connect(settings.database_url)
    try:
        tables = await conn.fetch("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        if tables:
            await conn.execute("TRUNCATE " + ", ".join(t["tablename"] for t in tables) + " CASCADE")
    finally:
        await conn.close()
    import redis.asyncio as aioredis
    r = aioredis.from_url(settings.redis_url)
    await r.flushdb()
    await r.aclose()


@contextlib.asynccontextmanager
async def environment(airlines: tuple[str, ...] = ("AC", "SQ", "EK", "QF", "AS", "QR"),
                      clock: SimClock | None = None, settings: Settings | None = None, persist: bool = True):
    settings = settings or test_settings()
    clock = clock or SimClock()
    await reset_stores(settings)
    app = create_app(settings)
    router = HostRouter()
    router.mount(VERIFY_HOST, app)
    async with httpx.AsyncClient(transport=router, timeout=30) as http, app.router.lifespan_context(app):
        # The simulator feeds the worker directly; stop the background stream flusher.
        app.state.events._task.cancel()
        envs: dict[str, AirlineEnv] = {}
        for code in airlines:
            key = generate_private_key()
            host = f"auth.{code.lower()}.test"
            issuer = f"http://{host}"
            jwk = {**public_jwk(key), "kid": jwk_thumbprint(public_jwk(key)), "alg": "EdDSA"}
            r = await http.post(f"http://{VERIFY_HOST}/v1/airlines", headers={"X-Admin-Key": ADMIN_KEY},
                                json={"airline_id": code, "name": f"Airline {code}", "issuer": issuer,
                                      "jwks": {"keys": [jwk]}})
            r.raise_for_status()
            as_app = create_as_app(code, issuer, key, f"http://{VERIFY_HOST}", http=http, clock=clock)
            router.mount(host, as_app)
            envs[code] = AirlineEnv(code, r.json()["api_key"], issuer, key, as_app)
        worker = RiskWorker(app.state.redis, app.state.pool, app.state.registry.policies, settings, persist=persist)
        yield Env(settings, app, http, clock, envs, worker)
