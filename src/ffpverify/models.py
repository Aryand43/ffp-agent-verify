"""Request / response models for the public API."""

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


class Decision(str, Enum):
    allow = "allow"
    flag = "flag"            # allow, but queued for review (authenticated lane)
    challenge = "challenge"  # serve a CAPTCHA / interstitial (unauthenticated lane)
    throttle = "throttle"    # 429 with Retry-After
    block = "block"


class Lane(str, Enum):
    authenticated = "authenticated"
    unauthenticated = "unauthenticated"


class ForwardedRequest(BaseModel):
    method: str = Field(examples=["GET"])
    url: str = Field(description="Full URL exactly as the tool requested it (scheme, host, path, query)",
                     examples=["https://api.airline.example/award/search?from=YVR&to=NRT&date=2026-12-01"])
    headers: dict[str, str] = Field(description="All request headers; must include Authorization, "
                                                "Signature-Input and Signature for signed requests")
    body_b64: str | None = Field(None, description="Request body, base64, if the signature covers content-digest")


class SearchInfo(BaseModel):
    origin: str = Field(min_length=3, max_length=3, examples=["YVR"])
    destination: str = Field(min_length=3, max_length=3, examples=["NRT"])
    date: str | None = Field(None, examples=["2026-12-01"])
    cabin: str | None = Field(None, examples=["business"])
    passengers: int = 1

    @property
    def route(self) -> str:
        return f"{self.origin.upper()}-{self.destination.upper()}"


class ClientSignals(BaseModel):
    device_id: str | None = Field(None, description="Airline's first-party device / session identifier")
    webdriver: bool | None = Field(None, description="navigator.webdriver from the airline's client script")
    bot_score: float | None = Field(None, ge=0, le=1, description="Edge bot-management score, 0 = human, 1 = bot")
    captcha: Literal["passed", "failed", "not_presented"] | None = None


class VerifyRequest(BaseModel):
    request: ForwardedRequest
    client_ip: str
    search: SearchInfo | None = None
    client_signals: ClientSignals = Field(default_factory=ClientSignals)


class Reason(BaseModel):
    signal: str
    strength: float | None = None
    points: float | None = None
    pillar: Literal["safety", "trust", "verifiability"] | None = Field(
        None, description="Which layer this signal belongs to (docs/framework.md)")
    detail: str
    advice: str = ""


class VerifyResponse(BaseModel):
    request_id: str
    decision: Decision
    lane: Lane
    score: float = Field(description="0-100; compared against the airline's thresholds")
    pillars: dict[str, float] | None = Field(
        None, description="The score split across safety / trust / verifiability (sums to score); "
                          "a failed hard check puts 100 on its own layer. Null when degraded.",
        examples=[{"safety": 0.0, "trust": 12.5, "verifiability": 41.3}])
    reasons: list[Reason]
    tool_id: str | None = None
    retry_after_s: int | None = None
    policy_version: int
    degraded: bool = Field(False, description="True if Redis was unavailable and the airline's fail mode applied")
    latency_us: int


class AirlineCreate(BaseModel):
    airline_id: str = Field(pattern=r"^[A-Z0-9]{2,3}$", examples=["AC"])
    name: str
    issuer: HttpUrl | str
    jwks: dict | None = None
    jwks_uri: str | None = None


class AirlineCreated(BaseModel):
    airline_id: str
    api_key: str = Field(description="Shown once. Send as X-Api-Key on /v1/search/verify.")


class ToolRegister(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    developer_contact: str = Field(min_length=3, max_length=200)
    public_jwk: dict = Field(description="Ed25519 public key as an OKP JWK")
    redirect_uris: list[str] = Field(default_factory=list)
    proof: str = Field(description="base64 Ed25519 signature over 'ffpv-register:<jkt>:<proof_ts>'")
    proof_ts: int


class ToolRegistered(BaseModel):
    tool_id: str
    jkt: str
    management_token: str = Field(description="Shown once. Send as X-Tool-Token for analytics and revocation.")


class RevokeRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class FeedbackLabel(str, Enum):
    false_positive = "false_positive"
    false_negative = "false_negative"
    confirmed_abuse = "confirmed_abuse"
    confirmed_legitimate = "confirmed_legitimate"


class FeedbackCreate(BaseModel):
    label: FeedbackLabel
    request_id: str | None = None
    tool_id: str | None = None
    notes: str | None = Field(None, max_length=2000)
