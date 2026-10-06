"""Traffic actors. Each `step` makes one or more verify calls and returns seconds until its next step
(None = done). Every outcome is recorded against the actor's label for FP / FN accounting."""

import base64
import random
from dataclasses import dataclass, field

from .harness import CHROME_HEADERS, Env, ToolEnv

AIRLINES = ("AC", "SQ", "EK", "QF", "AS", "QR")
HUBS = {"AC": ["YVR", "YYZ", "YUL"], "SQ": ["SIN"], "EK": ["DXB"], "QF": ["SYD", "MEL"], "AS": ["SEA", "ANC"],
        "QR": ["DOH"]}
DESTS = ["NRT", "HND", "LHR", "CDG", "FRA", "SIN", "HKG", "JFK", "LAX", "SYD", "DXB", "BKK", "ICN", "ZRH", "MLE"]

BROWSER_UAS = [
    CHROME_HEADERS,
    {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                   "Version/18.0 Mobile/15E148 Safari/604.1", "Accept": "text/html,*/*", "Accept-Language": "en-AU"},
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
     "Accept": "text/html,*/*", "Accept-Language": "en-US,en;q=0.5"},
]


def residential_ip(rng: random.Random) -> str:
    return f"{rng.choice([24, 66, 72, 99, 142, 174, 203])}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"


def datacenter_ip(rng: random.Random) -> str:
    return rng.choice([f"104.131.{rng.randrange(256)}.{rng.randrange(1, 255)}",
                       f"159.65.{rng.randrange(256)}.{rng.randrange(1, 255)}",
                       f"5.9.{rng.randrange(256)}.{rng.randrange(1, 255)}"])


def route(rng: random.Random, airline: str) -> tuple[str, str]:
    o = rng.choice(HUBS[airline])
    return o, rng.choice([d for d in DESTS if d != o])


@dataclass
class Outcome:
    t: float
    label: str
    decision: str
    reasons: list[str]
    latency_us: int


@dataclass
class Actor:
    label: str            # human | authorized | adversarial
    kind: str             # finer-grained scenario name
    rng: random.Random
    outcomes: list[Outcome] = field(default_factory=list)

    def record(self, env: Env, resp) -> None:
        self.outcomes.append(Outcome(env.clock(), self.label, resp.decision.value, [r.signal for r in resp.reasons],
                                     resp.latency_us))

    async def start(self, env: Env) -> float | None:
        return 0.0

    async def step(self, env: Env) -> float | None:
        raise NotImplementedError


# --- humans -------------------------------------------------------------------------------


class Human(Actor):
    """One award-search session: a handful of searches with think time, mostly one airline."""

    def __init__(self, rng, start_at: float, ip: str | None = None, kind="human", vpn=False, mobile=False):
        super().__init__("human", kind, rng)
        self.start_at = start_at
        self.airlines = [rng.choice(AIRLINES)] + ([rng.choice(AIRLINES)] if rng.random() < 0.15 else [])
        self.ip = ip or ("198.51.100." + str(rng.randrange(1, 255)) if vpn else residential_ip(rng))
        self.headers = rng.choice(BROWSER_UAS)
        self.devices = {a: f"dev-{rng.getrandbits(64):x}" for a in self.airlines}
        self.remaining = rng.randint(3, 12)
        self.mobile = mobile
        self.home_route = {a: route(rng, a) for a in self.airlines}

    async def start(self, env):
        return self.start_at

    async def step(self, env):
        a = self.rng.choice(self.airlines)
        o, d = self.home_route[a] if self.rng.random() < 0.5 else route(self.rng, a)
        if self.mobile and self.rng.random() < 0.15:
            self.ip = residential_ip(self.rng)  # carrier handoff
        self.record(env, await env.verify(env.browser_request(a, o, d, self.ip, headers=self.headers,
                                                              device_id=self.devices[a]), a))
        self.remaining -= 1
        return self.rng.uniform(15, 120) if self.remaining > 0 else None


# --- authorized tools -----------------------------------------------------------------------


class ToolWorker(Actor):
    """One tool polling one member's watched routes at one airline, like a seat-alert service."""

    def __init__(self, rng, tool: ToolEnv, airline: str, member: str, per_min: float, rotate_s: tuple[float, float],
                 kind="authorized", label="authorized"):
        super().__init__(label, kind, rng)
        self.tool, self.airline, self.member = tool, airline, member
        self.per_min = per_min
        self.rotate_s = rotate_s
        self.routes = [route(rng, airline) for _ in range(rng.randint(2, 4))]
        self.ip = datacenter_ip(rng) if rng.random() < 0.6 else residential_ip(rng)
        self.next_rotation = 0.0
        self.i = 0

    async def start(self, env):
        self.next_rotation = env.clock() + self.rng.uniform(*self.rotate_s)
        return env.clock() + self.rng.uniform(0, 60 / self.per_min)

    def maybe_rotate(self, env):
        if env.clock() >= self.next_rotation:
            self.ip = datacenter_ip(self.rng) if self.rng.random() < 0.6 else residential_ip(self.rng)
            self.next_rotation = env.clock() + self.rng.uniform(*self.rotate_s)

    async def step(self, env):
        self.maybe_rotate(env)
        tokens = await env.fresh_tokens(self.tool, self.airline, self.member)
        o, d = self.routes[self.i % len(self.routes)]
        self.i += 1
        resp = await env.verify(env.tool_request(self.tool, tokens, self.airline, o, d, self.ip), self.airline)
        self.record(env, resp)
        if resp.retry_after_s:  # well-behaved tools honour Retry-After
            return resp.retry_after_s + self.rng.uniform(0, 1)
        return self.rng.expovariate(self.per_min / 60) if self.rng.random() < 0.3 else 60 / self.per_min


# --- adversaries ----------------------------------------------------------------------------


class HighVelocityScraper(Actor):
    """No credentials, scripting UA or headless, all airlines, IP every few seconds."""

    def __init__(self, rng, per_min=90, headless=False):
        super().__init__("adversarial", "headless_scraper" if headless else "script_scraper", rng)
        self.per_min = per_min
        self.headers = ({**CHROME_HEADERS, "User-Agent": CHROME_HEADERS["User-Agent"].replace("Chrome", "HeadlessChrome")}
                        if headless else {"User-Agent": "python-requests/2.32.3", "Accept": "*/*"})
        self.ip, self.ip_until = None, 0.0

    async def step(self, env):
        if env.clock() >= self.ip_until:
            self.ip = datacenter_ip(self.rng) if self.rng.random() < 0.5 else residential_ip(self.rng)
            self.ip_until = env.clock() + self.rng.uniform(2, 6)
        a = self.rng.choice(AIRLINES)
        o, d = route(self.rng, a)
        self.record(env, await env.verify(env.browser_request(a, o, d, self.ip, headers=self.headers), a))
        return 60 / self.per_min


class StealthScraper(Actor):
    """Spoofed full browser headers, fresh residential proxy IP per request, no cookies. The hard case."""

    def __init__(self, rng, per_min=40):
        super().__init__("adversarial", "stealth_scraper", rng)
        self.per_min = per_min

    async def step(self, env):
        a = self.rng.choice(AIRLINES)
        o, d = route(self.rng, a)
        self.record(env, await env.verify(env.browser_request(a, o, d, residential_ip(self.rng)), a))
        return 60 / self.per_min


class CredentialFanout(ToolWorker):
    """A real grant driven by many parallel workers on rotating IPs (resold / shared credential)."""

    def __init__(self, rng, tool, airline, member, workers=8, per_min=100):
        super().__init__(rng, tool, airline, member, per_min, (3, 8), kind="credential_fanout", label="adversarial")
        self.workers = workers

    async def step(self, env):
        tokens = await env.fresh_tokens(self.tool, self.airline, self.member)
        o, d = self.routes[self.i % len(self.routes)]
        self.i += 1
        ip = f"185.156.172.{(int(env.clock() / 5) * self.workers + self.i % self.workers) % 250 + 1}"
        self.record(env, await env.verify(env.tool_request(self.tool, tokens, self.airline, o, d, ip), self.airline))
        return 60 / self.per_min  # ignores Retry-After


class Turncoat(ToolWorker):
    """Behaves like a good tool, then at `turn_at` starts hammering and rotating fast."""

    def __init__(self, rng, tool, airline, member, turn_at: float):
        super().__init__(rng, tool, airline, member, 15, (180, 600), kind="turncoat", label="authorized")
        self.turn_at = turn_at
        self.turned = False

    async def step(self, env):
        if not self.turned and env.clock() >= self.turn_at:
            self.turned, self.label, self.per_min, self.rotate_s = True, "adversarial", 120, (2, 5)
            self.next_rotation = env.clock()
        self.maybe_rotate(env)
        tokens = await env.fresh_tokens(self.tool, self.airline, self.member)
        o, d = self.routes[self.i % len(self.routes)]
        self.i += 1
        resp = await env.verify(env.tool_request(self.tool, tokens, self.airline, o, d, self.ip), self.airline)
        self.record(env, resp)  # recorded under the current label: authorized before the turn, adversarial after
        if not self.turned and resp.retry_after_s:
            return resp.retry_after_s
        return 60 / self.per_min


class TokenThief(Actor):
    """Holds stolen access tokens / captured signed requests from a victim tool."""

    def __init__(self, rng, own_tool: ToolEnv, victim: ToolEnv, victim_grant: tuple[str, str],
                 victim_worker: "ToolWorker"):
        super().__init__("adversarial", "token_thief", rng)
        self.own, self.victim, self.grant = own_tool, victim, victim_grant
        self.victim_worker = victim_worker  # the victim's own traffic comes from its own egress IP
        self.captured = []

    async def step(self, env):
        airline, member = self.grant
        tokens = await env.fresh_tokens(self.victim, airline, member)
        o, d = route(self.rng, airline)
        if self.rng.random() < 0.5:
            req = env.tool_request(self.own, tokens, airline, o, d, residential_ip(self.rng))   # token + own key
        else:
            # Replay a request the victim signed (captured in transit / from logs).
            req = env.tool_request(self.victim, tokens, airline, o, d, self.victim_worker.ip)
            if self.captured:
                req = self.captured.pop().model_copy(update={"client_ip": residential_ip(self.rng)})
            else:
                await env.verify(req, airline)  # the victim's own (legit) use of it
                self.captured.append(req)
                return 1.0
        self.record(env, await env.verify(req, airline))
        return 2.0


class Forger(Actor):
    """Puts a victim tool's keyid on garbage signatures, trying to get the victim penalized."""

    def __init__(self, rng, victim: ToolEnv, victim_grant):
        super().__init__("adversarial", "forger", rng)
        self.victim, self.grant = victim, victim_grant

    async def step(self, env):
        airline, member = self.grant
        tokens = await env.fresh_tokens(self.victim, airline, member)
        req = env.tool_request(self.victim, tokens, airline, *route(self.rng, airline), residential_ip(self.rng))
        h = dict(req.request.headers)
        h["Signature"] = "sig1=:" + base64.b64encode(self.rng.randbytes(64)).decode() + ":"
        req = req.model_copy(update={"request": req.request.model_copy(update={"headers": h})})
        self.record(env, await env.verify(req, airline))
        return 1.0


class RouteScopeAbuser(ToolWorker):
    """Member authorized a few routes; the tool searches others too."""

    def __init__(self, rng, tool, airline, member, allowed):
        super().__init__(rng, tool, airline, member, 10, (300, 600), kind="route_scope_abuser", label="adversarial")
        self.allowed = allowed

    async def step(self, env):
        tokens = await env.fresh_tokens(self.tool, self.airline, self.member)
        o, d = route(self.rng, self.airline)
        if f"{o}-{d}" in self.allowed:
            return 1.0
        self.record(env, await env.verify(env.tool_request(self.tool, tokens, self.airline, o, d, self.ip),
                                          self.airline))
        return 6.0
