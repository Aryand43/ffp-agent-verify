"""Per-airline policy: limits, tolerances, signal weights and decision thresholds."""

from enum import Enum

from pydantic import BaseModel, Field, model_validator


class VpnTolerance(str, Enum):
    allow = "allow"                            # VPN / datacenter IPs are fine for everyone
    authenticated_only = "authenticated_only"  # only verified agents may use them
    block = "block"                            # no VPN / datacenter traffic at all


class FailMode(str, Enum):
    open = "open"      # verifier unavailable -> allow (protects the search SLA)
    closed = "closed"  # verifier unavailable -> block


class UnauthenticatedMode(str, Enum):
    score = "score"          # heuristics decide allow / challenge / block
    challenge = "challenge"  # every unauthenticated request gets a challenge


# Every signal the scorer can emit. Each produces a strength s in [0, 1): 0 = normal,
# ~0.5 = clearly past the airline's tolerance, ~1 = unambiguous abuse. Signals combine as
# independent evidence: score = 100 * (1 - exp(-sum(w * -ln(1 - s)))), so one strong
# signal can block on its own and weak signals compound. Weight 0 disables a signal.
AUTH_SIGNALS = (
    "velocity",            # searches/min vs this airline's per-credential quota
    "ip_churn",            # IP changes/min vs acceptable rotation interval
    "ip_concurrency",      # distinct IPs used in parallel -> key/credential resale
    "grant_age",           # user authorization younger than the trust threshold
    "credential_sharing",  # one FFP account authorized for many tools, or one key across many accounts
    "verification_failures",  # recent replays / bad signatures from this tool
    "vpn",                 # datacenter / VPN egress (only if policy cares)
)
UNAUTH_SIGNALS = (
    "automation_headers",  # WebDriver / headless / scripting UA, missing browser headers
    "velocity",
    "ip_churn",
    "airline_coverage",    # same client fingerprint hitting many airlines (cross-airline view)
    "vpn",
    "external_bot_score",  # score forwarded from the airline's CDN bot management, if any
)


class Thresholds(BaseModel):
    challenge: float = 40
    throttle: float = 60
    block: float = 80
    revoke: float = 95  # authenticated tools only: auto-revoke key at or above this

    @model_validator(mode="after")
    def ordered(self):
        if not (0 <= self.challenge <= self.throttle <= self.block <= self.revoke <= 100):
            raise ValueError("thresholds must satisfy 0 <= challenge <= throttle <= block <= revoke <= 100")
        return self


def _default_auth_weights() -> dict[str, float]:
    return {"velocity": 3, "ip_churn": 2, "ip_concurrency": 3, "grant_age": 1, "credential_sharing": 2,
            "verification_failures": 3, "vpn": 0}


def _default_unauth_weights() -> dict[str, float]:
    return {"automation_headers": 3, "velocity": 3, "ip_churn": 2, "airline_coverage": 2, "vpn": 1,
            "external_bot_score": 2}


class AirlinePolicy(BaseModel):
    # Some airlines want zero automation, even authorized.
    authorized_agents_allowed: bool = True
    unauthenticated_mode: UnauthenticatedMode = UnauthenticatedMode.score

    # Hard rate limits (token buckets, enforced synchronously in Redis).
    max_searches_per_min_per_credential: int = Field(30, ge=1)
    max_searches_per_min_per_tool: int = Field(600, ge=1)       # across all of a tool's users at this airline
    # Per client: per device when the airline forwards a first-party device id, else per IP.
    max_searches_per_min_per_ip_unauthenticated: int = Field(20, ge=1)
    # With device ids, an IP may carry up to this many clients' worth of traffic (offices, carrier NAT).
    max_devices_per_ip: int = Field(10, ge=1)
    burst_multiplier: float = Field(1.5, ge=1.0)

    # Behavioral tolerances (feed the async scorer).
    min_ip_rotation_interval_s: int = Field(60, ge=0)   # rotating faster than this is suspicious
    max_concurrent_ips_per_credential: int = Field(2, ge=1)
    min_grant_age_s: int = Field(3600, ge=0)            # how long a user authorization must exist before full trust
    new_grant_rate_factor: float = Field(0.5, gt=0, le=1)  # quota multiplier while the grant is younger than that
    max_tools_per_member: int = Field(3, ge=1)
    vpn_tolerance: VpnTolerance = VpnTolerance.authenticated_only

    weights_authenticated: dict[str, float] = Field(default_factory=_default_auth_weights)
    weights_unauthenticated: dict[str, float] = Field(default_factory=_default_unauth_weights)
    thresholds: Thresholds = Field(default_factory=Thresholds)

    fail_mode: FailMode = FailMode.open

    @model_validator(mode="after")
    def known_signals(self):
        for name, allowed in (("weights_authenticated", AUTH_SIGNALS), ("weights_unauthenticated", UNAUTH_SIGNALS)):
            weights = getattr(self, name)
            unknown = set(weights) - set(allowed)
            if unknown:
                raise ValueError(f"{name}: unknown signals {sorted(unknown)}; allowed {list(allowed)}")
            if any(w < 0 for w in weights.values()):
                raise ValueError(f"{name}: weights must be >= 0")
        return self
