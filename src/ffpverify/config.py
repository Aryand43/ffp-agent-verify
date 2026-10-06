from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FFPV_", env_file=".env", extra="ignore")

    env: str = "dev"
    database_url: str = "postgresql://ffpv:ffpv@localhost:5432/ffpv"
    redis_url: str = "redis://localhost:6379/0"
    admin_key: str = "dev-admin-key"

    # Audience every airline-issued access token must carry.
    token_audience: str = "ffp-agent-verify"
    # Accepted clock skew for JWT exp/iat and signature `created`.
    clock_skew_s: int = 30
    # Max lifetime of an RFC 9421 signature (created -> expires).
    max_signature_age_s: int = 60
    # Hard ceiling on access-token lifetime we accept, regardless of issuer.
    max_token_lifetime_s: int = 15 * 60
    # Redis budget for the hot path; past this we fall back to the airline's fail mode.
    redis_timeout_ms: int = 20

    events_stream: str = "ffpv:events"
    events_stream_maxlen: int = 1_000_000


@lru_cache
def get_settings() -> Settings:
    return Settings()
