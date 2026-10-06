"""Verification of airline-issued access tokens (the airline runs the authorization server).

Expected claims (see docs/integration-airlines.md):
  iss, aud, sub, iat, exp, jti            standard; exp - iat <= 15 min
  client_id                               the tool_id registered with ffp-agent-verify
  scope                                   must include "award:search"
  cnf: {"jkt": <RFC 7638 thumbprint>}     binds the token to the tool's signing key
  auth_time                               when the member consented (grant age)
  ffp_routes (optional)                   ["YVR-NRT", ...] - search-specific credential
"""

import hashlib
from collections import OrderedDict
from dataclasses import dataclass

import jwt

ALLOWED_ALGS = ["EdDSA", "ES256"]
REQUIRED_SCOPE = "award:search"


class TokenError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class AccessToken:
    airline_id: str
    sub: str
    tool_id: str
    jkt: str
    jti: str
    iat: int
    exp: int
    auth_time: int | None
    routes: frozenset[str] | None

    @property
    def member_ref(self) -> str:
        return hashlib.sha256(f"{self.airline_id}:{self.sub}".encode()).hexdigest()[:32]

    @property
    def grant_id(self) -> str:
        return hashlib.sha256(f"{self.airline_id}:{self.tool_id}:{self.member_ref}".encode()).hexdigest()[:32]


class TokenVerifier:
    """Holds each airline's issuer + signing keys; caches successfully parsed tokens.

    Tokens are reused for many searches within their 5-15 min life, so the signature
    check runs once per token per process; expiry is still checked on every call.
    """

    def __init__(self, audience: str, skew_s: int, max_lifetime_s: int, cache_size: int = 50_000):
        self.audience = audience
        self.skew_s = skew_s
        self.max_lifetime_s = max_lifetime_s
        self._issuers: dict[str, tuple[str, dict[str, jwt.PyJWK]]] = {}  # airline_id -> (issuer, kid->key)
        self._raw: dict[str, tuple[str, dict]] = {}
        self._cache: OrderedDict[bytes, AccessToken] = OrderedDict()
        self._cache_size = cache_size

    def set_airline_keys(self, airline_id: str, issuer: str, jwks: dict) -> None:
        if self._raw.get(airline_id) == (issuer, jwks):
            return  # unchanged; keep the verified-token cache warm
        keys = {}
        for k in jwks.get("keys", []):
            pk = jwt.PyJWK(k)
            keys[k.get("kid") or pk.key_id or ""] = pk
        self._issuers[airline_id] = (issuer, keys)
        self._raw[airline_id] = (issuer, jwks)
        self._cache.clear()  # keys rotated: re-verify everything

    def remove_airline(self, airline_id: str) -> None:
        self._issuers.pop(airline_id, None)
        self._raw.pop(airline_id, None)
        self._cache.clear()

    def verify(self, token: str, airline_id: str, now: int) -> AccessToken:
        cache_key = hashlib.sha256(token.encode()).digest()
        at = self._cache.get(cache_key)
        if at is None:
            at = self._verify_uncached(token, airline_id)
            self._cache[cache_key] = at
            if len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
        if at.airline_id != airline_id:
            raise TokenError("wrong_airline", "credential was issued for a different airline")
        if now > at.exp + self.skew_s:
            raise TokenError("token_expired", "access token expired")
        if at.iat > now + self.skew_s:
            raise TokenError("token_not_yet_valid", "access token issued in the future")
        return at

    def _verify_uncached(self, token: str, airline_id: str) -> AccessToken:
        entry = self._issuers.get(airline_id)
        if entry is None:
            raise TokenError("unknown_airline", "no keys registered for this airline")
        issuer, keys = entry
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise TokenError("malformed_token", "access token is not a JWT") from None
        if header.get("alg") not in ALLOWED_ALGS:
            raise TokenError("bad_token_alg", f"alg {header.get('alg')} not allowed")
        kid = header.get("kid")
        # A kid must match exactly; only a kid-less token may fall back to a single-key JWKS.
        key = keys.get(kid) if kid else (next(iter(keys.values())) if len(keys) == 1 else None)
        if key is None:
            raise TokenError("unknown_kid", "token signed with an unknown key id")
        try:
            claims = jwt.decode(
                token, key=key, algorithms=ALLOWED_ALGS, audience=self.audience, issuer=issuer,
                options={"verify_exp": False, "verify_iat": False, "verify_nbf": False,
                         "require": ["iss", "aud", "sub", "iat", "exp", "jti"]},
            )
        except jwt.InvalidAudienceError:
            raise TokenError("bad_audience", "token audience is not ffp-agent-verify") from None
        except jwt.InvalidIssuerError:
            raise TokenError("bad_issuer", "token issuer does not match the airline") from None
        except jwt.PyJWTError as e:
            raise TokenError("bad_token", f"access token rejected: {e}") from None

        if REQUIRED_SCOPE not in str(claims.get("scope", "")).split():
            raise TokenError("insufficient_scope", f"token lacks scope {REQUIRED_SCOPE}")
        jkt = (claims.get("cnf") or {}).get("jkt")
        if not jkt:
            raise TokenError("unbound_token", "token has no cnf.jkt key binding")
        if not claims.get("client_id"):
            raise TokenError("bad_token", "token has no client_id")
        if int(claims["exp"]) - int(claims["iat"]) > self.max_lifetime_s:
            raise TokenError("token_lifetime_too_long", f"token lifetime exceeds {self.max_lifetime_s}s")
        routes = claims.get("ffp_routes")
        return AccessToken(
            airline_id=airline_id, sub=str(claims["sub"]), tool_id=str(claims["client_id"]), jkt=jkt,
            jti=str(claims["jti"]), iat=int(claims["iat"]), exp=int(claims["exp"]),
            auth_time=int(claims["auth_time"]) if "auth_time" in claims else None,
            routes=frozenset(r.upper() for r in routes) if routes else None,
        )
