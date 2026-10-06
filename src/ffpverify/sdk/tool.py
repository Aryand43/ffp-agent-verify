"""Tool-side SDK: register a key, run the OAuth flow with an airline, sign searches.

    key = generate_private_key()
    reg = await ToolClient.register(http, "https://verify.example", "SeatWatch", "ops@seatwatch.example",
                                    ["https://seatwatch.example/cb"], key)
    tool = ToolClient(reg["tool_id"], key, http)
    url, state, verifier = tool.authorization_url("https://auth.airline.example", "https://seatwatch.example/cb",
                                                  routes=["YVR-NRT"])
    # ... member approves, airline redirects back with ?code=...
    tokens = await tool.exchange_code("https://auth.airline.example", code, verifier, redirect_uri)
    headers = tool.sign("GET", search_url, {"Accept": "application/json"}, tokens.access_token)
"""

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .. import httpsig
from ..crypto import b64url, jwk_thumbprint, public_jwk


@dataclass
class Tokens:
    access_token: str
    refresh_token: str
    expires_at: float

    def needs_refresh(self, now: float | None = None, margin_s: float = 60) -> bool:
        return (now or time.time()) > self.expires_at - margin_s


class ToolClient:
    def __init__(self, tool_id: str, key: Ed25519PrivateKey, http: httpx.AsyncClient | None = None, clock=time.time):
        self.tool_id = tool_id
        self.key = key
        self.jwk = public_jwk(key)
        self.jkt = jwk_thumbprint(self.jwk)
        self.http = http or httpx.AsyncClient(timeout=10)
        self.clock = clock

    @staticmethod
    async def register(http: httpx.AsyncClient, registry_url: str, name: str, contact: str,
                       redirect_uris: list[str], key: Ed25519PrivateKey) -> dict:
        jwk = public_jwk(key)
        ts = int(time.time())
        proof = base64.b64encode(key.sign(f"ffpv-register:{jwk_thumbprint(jwk)}:{ts}".encode())).decode()
        r = await http.post(f"{registry_url}/v1/tools/register", json={
            "name": name, "developer_contact": contact, "public_jwk": jwk, "redirect_uris": redirect_uris,
            "proof": proof, "proof_ts": ts})
        r.raise_for_status()
        return r.json()

    # --- OAuth ---------------------------------------------------------------------

    def authorization_url(self, as_base: str, redirect_uri: str, routes: list[str] | None = None,
                          scope: str = "award:search") -> tuple[str, str, str]:
        """Returns (url to send the member to, state, PKCE verifier)."""
        verifier = secrets.token_urlsafe(48)
        state = secrets.token_urlsafe(16)
        params = {"response_type": "code", "client_id": self.tool_id, "redirect_uri": redirect_uri,
                  "state": state, "scope": scope, "code_challenge_method": "S256",
                  "code_challenge": b64url(hashlib.sha256(verifier.encode()).digest()), "dpop_jkt": self.jkt}
        if routes:
            params["ffp_routes"] = ",".join(routes)
        return f"{as_base}/oauth/authorize?{urlencode(params)}", state, verifier

    def client_assertion(self, audience: str) -> str:
        now = int(self.clock())
        return jwt.encode({"iss": self.tool_id, "sub": self.tool_id, "aud": audience, "iat": now, "exp": now + 60,
                           "jti": secrets.token_urlsafe(16)}, self.key, algorithm="EdDSA", headers={"kid": self.jkt})

    async def _token(self, as_base: str, form: dict) -> Tokens:
        endpoint = f"{as_base}/oauth/token"
        r = await self.http.post(endpoint, data={
            **form, "client_id": self.tool_id,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": self.client_assertion(endpoint)})
        r.raise_for_status()
        body = r.json()
        return Tokens(body["access_token"], body["refresh_token"], self.clock() + body["expires_in"])

    async def exchange_code(self, as_base: str, code: str, verifier: str, redirect_uri: str) -> Tokens:
        return await self._token(as_base, {"grant_type": "authorization_code", "code": code,
                                           "code_verifier": verifier, "redirect_uri": redirect_uri})

    async def refresh(self, as_base: str, refresh_token: str) -> Tokens:
        return await self._token(as_base, {"grant_type": "refresh_token", "refresh_token": refresh_token})

    # --- request signing ------------------------------------------------------------------

    def sign(self, method: str, url: str, headers: dict[str, str], access_token: str, *,
             now: int | None = None, body: bytes | None = None, ttl_s: int = 30) -> dict[str, str]:
        """Returns `headers` plus Authorization, Signature-Input, Signature (and Content-Digest for a body)."""
        out = dict(headers)
        out["Authorization"] = f"Bearer {access_token}"
        components = httpsig.DEFAULT_COMPONENTS
        if body is not None:
            out["Content-Digest"] = httpsig.content_digest(body)
            components = components + ("content-digest",)
        out.update(httpsig.sign_request(self.key, self.jkt, method, url, out,
                                        created=now if now is not None else int(self.clock()),
                                        nonce=secrets.token_urlsafe(16), ttl_s=ttl_s, components=components))
        return out
